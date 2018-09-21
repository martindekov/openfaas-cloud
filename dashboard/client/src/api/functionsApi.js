import axios from 'axios';
import moment from 'moment';

class FunctionsApi {
  constructor() {
    this.selectedRepo = '';
    this.prettyDomain = window.PRETTY_URL;
    this.queryPrettyUrl = window.QUERY_PRETTY_URL === 'true';

    if (process.env.NODE_ENV === 'production') {
      this.baseURL = window.PUBLIC_URL;
      this.apiBaseUrl = `${window.BASE_HREF}api`;
    } else {
      this.baseURL = 'http://127.0.0.1:8080';
      this.apiBaseUrl = '/api';
    }

    this.cachedFunctions = {};
  }

  parseFunctionResponse({ data }, user) {
    data.sort((a, b) => {
      if (
        !a ||
        !b ||
        (!a.labels['com.openfaas.cloud.git-deploytime'] || !b.labels['com.openfaas.cloud.git-deploytime'])
      ) {
        return 0;
      }
      return (
        parseInt(b.labels['com.openfaas.cloud.git-deploytime'], 10) -
        parseInt(a.labels['com.openfaas.cloud.git-deploytime'], 10)
      );
    });

    const userPrefixRegex = new RegExp(`^${user}-`);

    return data.map(item => {
      const since = new Date(
        parseInt(item.labels['com.openfaas.cloud.git-deploytime'], 10) * 1000
      );
      const sinceDuration = moment(since).fromNow();

      const shortName = item.name.replace(userPrefixRegex, '');

      let endpoint;

      if (this.queryPrettyUrl) {
        endpoint = this.prettyDomain
          .replace('user', user)
          .replace('function', shortName);
      } else {
        endpoint = this.baseURL + '/function/' + item.name;
      }

      let shortSha = item.labels['com.openfaas.cloud.git-sha'];
      if (shortSha) {
        shortSha = shortSha.substr(0, 7);
      } else {
        shortSha = 'unknown';
      }

      return {
        name: item.name,
        image: item.image,
        shortName,
        endpoint,
        shortSha,
        sinceDuration,
        invocationCount: item.invocationCount,
        replicas: item.replicas,
        gitRepo: item.labels['com.openfaas.cloud.git-repo'],
        gitOwner: item.labels['com.openfaas.cloud.git-owner'],
        gitDeployTime: item.labels['com.openfaas.cloud.git-deploytime'],
        gitSha: item.labels['com.openfaas.cloud.git-sha'],
        minReplicas: item.labels['com.openfaas.scale.min'],
        maxReplicas: item.labels['com.openfaas.scale.max'],
      };
    });
  }
  fetchFunctions(user) {
    const url = `${this.apiBaseUrl}/list-functions?user=${user}`;
    return axios
      .get(url)
      .then(res => this.parseFunctionResponse(res, user))
      .then(data => {
        this.cachedFunctions = data.reduce((cache, fn) => {
          cache[`${user}/${fn.gitOwner}/${fn.gitRepo}/${fn.shortName}`] = fn;
          return cache;
        }, {});
        return data;
      });
  }

  fetchFunction(user, gitRepo, fnShortname) {
    return new Promise((resolve, reject) => {
      const key = `${user}/${gitRepo}/${fnShortname}`;

      const cachedFn = this.cachedFunctions[key];
      if (cachedFn) {
        resolve(cachedFn);
        return;
      }

      // fetch functions if cache not found
      this.fetchFunctions(user).then(() => {
        const fn = this.cachedFunctions[key];
        fn !== undefined
          ? resolve(fn)
          : reject(new Error(`Function ${key} not found`));
      });
    });
  }

  fetchFunctionLog({ commitSHA, repoPath, functionName }) {
    const url = `${
      this.apiBaseUrl
    }/pipeline-log?commitSHA=${commitSHA}&repoPath=${repoPath}&function=${functionName}`;
    return axios.get(url).then(res => {
      return res.data;
    });
  }
}

export const functionsApi = new FunctionsApi();
