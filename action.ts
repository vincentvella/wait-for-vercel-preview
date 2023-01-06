import * as core from '@actions/core'
import * as github from '@actions/github'
import axios from 'axios'
import setCookieParser from 'set-cookie-parser'

type Kit = ReturnType<typeof github.getOctokit>

const calculateIterations = (maxTimeoutSec: number, checkIntervalInMilliseconds: number) =>
	Math.floor(maxTimeoutSec / (checkIntervalInMilliseconds / 1000));

const wait = (ms: number) => new Promise((resolve) => setTimeout(resolve, ms));

const waitForUrl = async ({
	url,
	maxTimeout,
	checkIntervalInMilliseconds,
	vercelPassword,
	path,
}) => {
	const iterations = calculateIterations(
		maxTimeout,
		checkIntervalInMilliseconds
	);

	for (let i = 0; i < iterations; i++) {
		try {
			let headers: Record<string, string> = { "Accept-Encoding": "gzip,deflate,compress" };

			if (vercelPassword) {
				const jwt = await getPassword({
					url,
					vercelPassword,
				});

				headers['Cookie'] = `_vercel_jwt=${jwt}`;

				core.setOutput('vercel_jwt', jwt);
			}

			let checkUri = new URL(path, url);
			console.log('sending request to: ', checkUri.toString())
			await axios.get(checkUri.toString(), {
				headers,
			});
			console.log('Received success status code');
			return;
		} catch (e) {
			// https://axios-http.com/docs/handling_errors
			if (e.response) {
				console.log(
					`GET status: ${e.response.status}. Attempt ${i} of ${iterations}`
				);
			} else if (e.request) {
				console.log(
					`GET error. A request was made, but no response was received. Attempt ${i} of ${iterations}`
				);
				console.log(e.message);
			} else {
				console.log(e);
			}

			await wait(checkIntervalInMilliseconds);
		}
	}

	core.setFailed(`Timeout reached: Unable to connect to ${url}`);
};

/**
 * See https://vercel.com/docs/errors#errors/bypassing-password-protection-programmatically
 * @param {{url: string; vercelPassword: string }} options vercel password options
 * @returns {Promise<string>}
 */
const getPassword = async ({ url, vercelPassword }) => {
	console.log('requesting vercel JWT');

	const data = new URLSearchParams();
	data.append('_vercel_password', vercelPassword);

	const response = await axios({
		url,
		method: 'post',
		data: data.toString(),
		headers: {
			'content-type': 'application/x-www-form-urlencoded',
		},
		maxRedirects: 0,
		validateStatus: (status) => {
			// Vercel returns 303 with the _vercel_jwt
			return status >= 200 && status < 307;
		},
	});

	const setCookieHeader = response.headers['set-cookie'];

	if (!setCookieHeader) {
		throw new Error('no vercel JWT in response');
	}

	const cookies = setCookieParser(setCookieHeader);

	const vercelJwtCookie = cookies.find(
		(cookie) => cookie.name === '_vercel_jwt'
	);

	if (!vercelJwtCookie || !vercelJwtCookie.value) {
		throw new Error('no vercel JWT in response');
	}

	console.log('received vercel JWT');

	return vercelJwtCookie.value;
};

type Status = Awaited<ReturnType<Kit['rest']['repos']['listDeploymentStatuses']>>['data'][number]
const waitForStatus = async ({
	token,
	owner,
	repo,
	deployment_id,
	maxTimeout,
	allowInactive,
	checkIntervalInMilliseconds,
}): Promise<Status> => {
	const octokit = github.getOctokit(token);
	const iterations = calculateIterations(
		maxTimeout,
		checkIntervalInMilliseconds
	);

	for (let i = 0; i < iterations; i++) {
		try {
			const statuses = await octokit.rest.repos.listDeploymentStatuses({
				owner,
				repo,
				deployment_id,
			});

			const status = statuses.data.length > 0 && statuses.data[0];

			if (!status) {
				throw new StatusError('No status was available');
			}

			if (status && allowInactive === true && status.state === 'inactive') {
				return status;
			}

			if (status && status.state !== 'success') {
				throw new StatusError('No status with state "success" was available');
			}

			if (status && status.state === 'success') {
				return status;
			}

			throw new StatusError('Unknown status error');
		} catch (e) {
			console.log(
				`Deployment unavailable or not successful, retrying (attempt ${i + 1
				} / ${iterations})`
			);
			if (e instanceof StatusError) {
				if (e.message.includes('No status with state "success"')) {
					// TODO: does anything actually need to be logged in this case?
				} else {
					console.log(e.message);
				}
			} else {
				console.log(e);
			}
			await wait(checkIntervalInMilliseconds);
		}
	}
	core.setFailed(
		`Timeout reached: Unable to wait for an deployment to be successful`
	);
};

class StatusError extends Error {
	constructor(message) {
		super(message);
	}
}

type DeploymentParameters = {
	expectedDeployments?: number;
	octokit: Kit;
	deployment?: string;
	owner: string;
	repo: string;
	sha: string;
	environment: string;
	actorName: string;
	maxTimeout?: number;
	checkIntervalInMilliseconds?: number;
}

type Deployment = Awaited<ReturnType<Kit['rest']['repos']['listDeployments']>>['data'][number]

const stripEnvironmentFromName = (name: string) => name.replace('Preview – ', '').replace('Production – ', '')

/**
 * Waits until the github API returns a deployment for
 * a given actor.
 *
 * Accounts for race conditions where this action starts
 * before the actor's action has started.
 *
 * @returns
 */
const waitForDeploymentsToStart = async ({
	expectedDeployments = 1,
	octokit,
	deployment,
	owner,
	repo,
	sha,
	environment,
	actorName,
	maxTimeout = 20,
	checkIntervalInMilliseconds = 2000,
}: DeploymentParameters): Promise<Deployment | Deployment[]> => {
	const iterations = calculateIterations(
		maxTimeout,
		checkIntervalInMilliseconds
	);

	for (let i = 0; i < iterations; i++) {
		try {
			const deployments = await octokit.rest.repos.listDeployments({
				owner,
				repo,
				sha,
				environment,
			});

			const foundDeployments: Deployment[] =
				deployments.data.length > 0 &&
				deployments.data.filter((deployment) => deployment.creator.login === actorName);

			if (deployment) {
				const foundDeployment = foundDeployments.find(dep => (stripEnvironmentFromName(dep.environment) === deployment))
				if (foundDeployment) {
					return foundDeployment
				} else {
					console.log('Deployments in progress, deployment not ready')
				}
			} else {
				if (foundDeployments.length === expectedDeployments) {
					return foundDeployments;
				} else if (foundDeployments.length !== 0 && foundDeployments.length !== expectedDeployments) {
					console.log(`Deployments in progress.... ( ${foundDeployments.length}/${expectedDeployments} complete )`)
				} else {
					console.log(`Could not find any deployments for actor ${actorName}, retrying (attempt ${i + 1} / ${iterations})`);
				}
			}

		} catch (e) {
			console.log(`Error while fetching deployments, retrying (attempt ${i + 1} / ${iterations})`);

			console.error(e)
		}

		await wait(checkIntervalInMilliseconds);
	}

	return null;
};

async function getShaForPullRequest({ octokit, owner, repo, number }) {
	const PR_NUMBER = github.context.payload.pull_request.number;

	if (!PR_NUMBER) {
		core.setFailed('No pull request number was found');
		return;
	}

	// Get information about the pull request
	const currentPR = await octokit.rest.pulls.get({
		owner,
		repo,
		pull_number: PR_NUMBER,
	});

	if (currentPR.status !== 200) {
		core.setFailed('Could not get information about the current pull request');
		return;
	}

	// Get Ref from pull request
	const prSHA = currentPR.data.head.sha;

	return prSHA;
}

const handleStatus = ({ MAX_TIMEOUT, CHECK_INTERVAL_IN_MS, VERCEL_PASSWORD, PATH, handleSingleOutput = false }) => async (status: Status) => {
	// Get target url
	const environmentUrl = status.environment_url;
	if (!environmentUrl) {
		core.setFailed(`no target_url found in the status check`);
		return;
	}

	const projectName = stripEnvironmentFromName(status.environment)
	console.log('project name »', projectName)
	console.log('target url »', environmentUrl);

	// Set output
	if (handleSingleOutput) {
		core.setOutput('url', environmentUrl)
	} else {
		core.setOutput(`app-${projectName}`, environmentUrl);
	}

	// Wait for url to respond with a success
	console.log(`Waiting for a status code 200 from: ${environmentUrl}`);

	try {

		await waitForUrl({
			url: environmentUrl,
			maxTimeout: MAX_TIMEOUT,
			checkIntervalInMilliseconds: CHECK_INTERVAL_IN_MS,
			vercelPassword: VERCEL_PASSWORD,
			path: PATH,
		})
	} catch (error) {
		core.setFailed(error.message);
	}
}

export const run = async () => {
	try {
		// Inputs
		const GITHUB_TOKEN = core.getInput('token', { required: true });
		const VERCEL_PASSWORD = core.getInput('vercel_password');
		const ENVIRONMENT = core.getInput('environment');
		const actorName = core.getInput('actor') || 'vercel[bot]';
		const expectedDeployments = Number(core.getInput('expected_deployments')) || 1;
		const MAX_TIMEOUT = Number(core.getInput('max_timeout')) || 60;
		const ALLOW_INACTIVE = Boolean(core.getInput('allow_inactive')) || false;
		const PATH = core.getInput('path') || '/';
		const CHECK_INTERVAL_IN_MS =
			(Number(core.getInput('check_interval')) || 2) * 1000;
		const deployment = core.getInput('deployment')

		// Fail if we have don't have a github token
		if (!GITHUB_TOKEN) {
			core.setFailed('Required field `token` was not provided');
		}

		const octokit = github.getOctokit(GITHUB_TOKEN);

		const context = github.context;
		const owner = context.repo.owner;
		const repo = context.repo.repo;

		/**
		 * @type {string}
		 */
		let sha;

		if (github.context.payload && github.context.payload.pull_request) {
			sha = await getShaForPullRequest({
				octokit,
				owner,
				repo,
				number: github.context.payload.pull_request.number,
			});
		} else if (github.context.sha) {
			sha = github.context.sha;
		}

		if (!sha) {
			core.setFailed('Unable to determine SHA. Exiting...');
			return;
		}

		// Get deployments associated with the pull request.
		const deployments = await waitForDeploymentsToStart({
			expectedDeployments,
			deployment,
			octokit,
			owner,
			repo,
			sha: sha,
			environment: ENVIRONMENT,
			actorName,
			maxTimeout: MAX_TIMEOUT,
			checkIntervalInMilliseconds: CHECK_INTERVAL_IN_MS,
		});

		// Handles num of array scenario
		if (Array.isArray(deployments)) {
			if (!deployments.length) {
				core.setFailed('no vercel deployments found, exiting...');
				return;
			}

			await Promise.all(deployments.map((deployment) => new Promise<void>(resolve => {
				waitForStatus({
					owner,
					repo,
					deployment_id: deployment.id,
					token: GITHUB_TOKEN,
					maxTimeout: MAX_TIMEOUT,
					allowInactive: ALLOW_INACTIVE,
					checkIntervalInMilliseconds: CHECK_INTERVAL_IN_MS,
				}).then(status => handleStatus({ CHECK_INTERVAL_IN_MS, MAX_TIMEOUT, PATH, VERCEL_PASSWORD })(status).then(() => resolve()))
			})))
		} else if (!!deployments) {
			// Handles specific deployment scenario
			const status = await waitForStatus({
				owner,
				repo,
				deployment_id: deployments.id,
				token: GITHUB_TOKEN,
				maxTimeout: MAX_TIMEOUT,
				allowInactive: ALLOW_INACTIVE,
				checkIntervalInMilliseconds: CHECK_INTERVAL_IN_MS,
			})
			await handleStatus({ CHECK_INTERVAL_IN_MS, MAX_TIMEOUT, PATH, VERCEL_PASSWORD, handleSingleOutput: true })(status)
		}

	} catch (error) {
		core.setFailed(error.message);
	}
};
