import { createDatabase, TinaLevelClient } from "@tinacms/datalayer";
import { MongodbLevel } from "mongodb-level";
import { Octokit } from "@octokit/rest";
import { Base64 } from "js-base64";
import path from "path";
import fs from "fs";

// Manage this flag in your CI/CD pipeline and make sure it is set to false in production
const isLocal = process.env.TINA_PUBLIC_IS_LOCAL === "true";

if (isLocal) console.log("Running TinaCMS in local mode.");
else console.log("Running TinaCMS in production mode.");

const token = process.env.GITHUB_PERSONAL_ACCESS_TOKEN as string;
const owner = (process.env.GITHUB_OWNER ||
  process.env.VERCEL_GIT_REPO_OWNER) as string;
const repo = (process.env.GITHUB_REPO ||
  process.env.VERCEL_GIT_REPO_SLUG) as string;
const branch = (process.env.GITHUB_BRANCH ||
  process.env.VERCEL_GIT_COMMIT_REF ||
  "main") as string;

const octokit = new Octokit({
  auth: token,
});

const localLevelStore = new TinaLevelClient();

const mongodbLevelStore = new MongodbLevel<string, Record<string, any>>({
  collectionName: "tinacms",
  dbName: "tinacms",
  mongoUri: process.env.MONGODB_URI,
});
if (isLocal) localLevelStore.openConnection();

const githubOnPut = async (key, value) => {
  let sha;
  try {
    const {
      // @ts-ignore
      data: { sha: existingSha },
    } = await octokit.repos.getContent({
      owner,
      repo,
      path: key,
      ref: branch,
    });
    sha = existingSha;
  } catch (e) {
    console.log(e);
  }

  await octokit.repos.createOrUpdateFileContents({
    owner,
    repo,
    path: key,
    message: "commit from self-hosted tina",
    content: Base64.encode(value),
    branch,
    sha,
  });
};
const localOnPut = async (key, value) => {
  const currentPath = path.join(process.cwd(), key);
  fs.writeFileSync(currentPath, value);
};

const githubOnDelete = async (key) => {
  let sha;
  try {
    const {
      // @ts-ignore
      data: { sha: existingSha },
    } = await octokit.repos.getContent({
      owner,
      repo,
      path: key,
      ref: branch,
    });
    sha = existingSha;
  } catch (e) {}

  if (sha) {
    await octokit.repos.deleteFile({
      owner,
      repo,
      path: key,
      message: "commit from self-hosted tina",
      branch,
      sha,
    });
  } else {
    throw new Error(`Could not find file ${key} in repo ${owner}/${repo}`);
  }
};
const localOnDelete = async (key) => {
  const currentPath = path.join(process.cwd(), key);
  fs.rmSync(currentPath);
};

export default createDatabase({
  level: isLocal ? localLevelStore : mongodbLevelStore,
  onPut: isLocal ? localOnPut : githubOnPut,
  onDelete: isLocal ? localOnDelete : githubOnDelete,
});
