import * as sinon from 'sinon';
import * as _ from 'lodash';

interface AcceptanceTests {
  language: string;
  tests: {
    [name: string]: any;
  };
}

export const AllProjectsTests: AcceptanceTests = {
  language: 'Mixed',
  tests: {
    '`monitor mono-repo-project with lockfiles --all-projects`': (
      params,
      utils,
    ) => async (t) => {
      utils.chdirWorkspaces();
      // mock python plugin becuase CI tooling doesn't have pipenv installed
      const mockPlugin = {
        async inspect() {
          return {
            plugin: {
              targetFile: 'Pipfile',
              name: 'snyk-python-plugin',
            },
            package: {},
          };
        },
      };
      const loadPlugin = sinon.stub(params.plugins, 'loadPlugin');
      t.teardown(loadPlugin.restore);
      loadPlugin.withArgs('pip').returns(mockPlugin);
      loadPlugin.callThrough();

      const result = await params.cli.monitor('mono-repo-project', {
        allProjects: true,
        detectionDepth: 1,
      });
      t.ok(loadPlugin.withArgs('rubygems').calledOnce, 'calls rubygems plugin');
      t.ok(loadPlugin.withArgs('npm').calledOnce, 'calls npm plugin');
      t.ok(loadPlugin.withArgs('maven').calledOnce, 'calls maven plugin');
      t.ok(loadPlugin.withArgs('pip').calledOnce, 'calls python plugin');

      // npm
      t.match(
        result,
        'npm/graph/some/project-id',
        'npm project was monitored (via graph endpoint)',
      );
      // rubygems
      t.match(
        result,
        'rubygems/some/project-id',
        'rubygems project was monitored',
      );
      // maven
      t.match(result, 'maven/some/project-id', 'maven project was monitored ');
      // python
      t.match(result, 'pip/some/project-id', 'python project was monitored ');

      // Pop all calls to server and filter out calls to `featureFlag` endpoint
      const requests = params.server
        .popRequests(5)
        .filter((req) => req.url.includes('/monitor/'));
      t.equal(requests.length, 4, 'Correct amount of monitor requests');

      requests.forEach((req) => {
        t.match(
          req.url,
          /\/api\/v1\/monitor\/(npm\/graph|rubygems|maven|pip)/,
          'puts at correct url',
        );
        if (req.url === '/api/v1/monitor/pip') {
          t.equals(req.body.targetFile, 'Pipfile', 'sends targetFile=Pipfile');
        } else {
          t.notOk(
            req.body.targetFile,
            `doesn't send the targetFile for ${req.url}`,
          );
        }
        t.equal(req.method, 'PUT', 'makes PUT request');
        t.equal(
          req.headers['x-snyk-cli-version'],
          params.versionNumber,
          'sends version number',
        );
      });
    },
    '`monitor maven-multi-app --all-projects --detection-depth=2`': (
      params,
      utils,
    ) => async (t) => {
      utils.chdirWorkspaces();
      const spyPlugin = sinon.spy(params.plugins, 'loadPlugin');
      t.teardown(spyPlugin.restore);

      const result = await params.cli.monitor('maven-multi-app', {
        allProjects: true,
        detectionDepth: 2,
      });
      t.ok(
        spyPlugin.withArgs('rubygems').notCalled,
        'did not call rubygems plugin',
      );
      t.ok(spyPlugin.withArgs('npm').notCalled, 'did not call npm plugin');
      t.equals(
        spyPlugin.withArgs('maven').callCount,
        2,
        'calls maven plugin twice',
      );
      // maven
      t.match(result, 'maven/some/project-id', 'maven project was monitored ');

      const requests = params.server.popRequests(2);

      requests.forEach((request) => {
        // once we have depth increase released
        t.ok(request, 'Monitor POST request');

        t.match(request.url, '/monitor/', 'puts at correct url');
        t.notOk(request.body.targetFile, "doesn't send the targetFile");
        t.equal(request.method, 'PUT', 'makes PUT request');
        t.equal(
          request.headers['x-snyk-cli-version'],
          params.versionNumber,
          'sends version number',
        );
      });
    },
    '`monitor monorepo-bad-project --all-projects`': (params, utils) => async (
      t,
    ) => {
      utils.chdirWorkspaces();
      const spyPlugin = sinon.spy(params.plugins, 'loadPlugin');
      t.teardown(spyPlugin.restore);

      const result = await params.cli.monitor('monorepo-bad-project', {
        allProjects: true,
      });
      t.ok(spyPlugin.withArgs('rubygems').calledOnce, 'calls rubygems plugin');
      t.ok(spyPlugin.withArgs('yarn').calledOnce, 'calls npm plugin');
      t.ok(spyPlugin.withArgs('maven').notCalled, 'did not call  maven plugin');

      // rubygems
      t.match(
        result,
        'rubygems/some/project-id',
        'rubygems project was monitored',
      );
      // yarn
      // yarn project fails with OutOfSyncError, no monitor output shown
      const request = params.server.popRequest();

      t.ok(request, 'Monitor POST request');

      t.match(request.url, '/monitor/', 'puts at correct url');
      t.notOk(request.body.targetFile, "doesn't send the targetFile");
      t.equal(request.method, 'PUT', 'makes PUT request');
      t.equal(
        request.headers['x-snyk-cli-version'],
        params.versionNumber,
        'sends version number',
      );
    },
    '`monitor mono-repo-project --all-projects sends same payload as --file`': (
      params,
      utils,
    ) => async (t) => {
      utils.chdirWorkspaces();

      // mock python plugin becuase CI tooling doesn't have pipenv installed
      const mockPlugin = {
        async inspect() {
          return {
            plugin: {
              targetFile: 'Pipfile',
              name: 'snyk-python-plugin',
            },
            package: {},
          };
        },
      };
      const loadPlugin = sinon.stub(params.plugins, 'loadPlugin');
      t.teardown(loadPlugin.restore);
      loadPlugin.withArgs('pip').returns(mockPlugin);
      loadPlugin.callThrough();

      await params.cli.monitor('mono-repo-project', {
        allProjects: true,
        detectionDepth: 1,
      });

      // Pop all calls to server and filter out calls to `featureFlag` endpoint
      const [rubyAll, pipAll, npmAll, mavenAll] = params.server
        .popRequests(5)
        .filter((req) => req.url.includes('/monitor/'));

      await params.cli.monitor('mono-repo-project', {
        file: 'Gemfile.lock',
      });
      const rubyFile = params.server.popRequest();

      await params.cli.monitor('mono-repo-project', {
        file: 'package-lock.json',
      });
      const npmFile = params.server.popRequest();

      await params.cli.monitor('mono-repo-project', {
        file: 'pom.xml',
      });
      const mavenFile = params.server.popRequest();

      await params.cli.monitor('mono-repo-project', {
        file: 'Pipfile',
      });
      const pipFile = params.server.popRequest();

      t.same(
        rubyAll.body,
        rubyFile.body,
        'Same body for --all-projects and --file=Gemfile.lock',
      );

      t.same(
        npmAll.body,
        npmFile.body,
        'Same body for --all-projects and --file=package-lock.json',
      );

      t.same(
        pipAll.body,
        pipFile.body,
        'Same body for --all-projects and --file=Pipfile',
      );

      t.same(
        mavenAll.body,
        mavenFile.body,
        'Same body for --all-projects and --file=pom.xml',
      );
    },
    '`monitor composer-app with --all-projects and without same meta`': (
      params,
      utils,
    ) => async (t) => {
      utils.chdirWorkspaces();
      const spyPlugin = sinon.spy(params.plugins, 'loadPlugin');
      t.teardown(spyPlugin.restore);

      await params.cli.monitor('composer-app', {
        allProjects: true,
      });
      // Pop all calls to server and filter out calls to `featureFlag` endpoint
      const [composerAll] = params.server
        .popRequests(2)
        .filter((req) => req.url.includes('/monitor/'));

      await params.cli.monitor('composer-app', {
        file: 'composer.lock',
      });
      const [requestsComposer] = params.server
        .popRequests(2)
        .filter((req) => req.url.includes('/monitor/'));

      t.deepEqual(
        composerAll.body,
        requestsComposer.body,
        'Same body for --all-projects and --file=composer.lock',
      );
    },
    '`monitor mono-repo-project with lockfiles --all-projects --json`': (
      params,
      utils,
    ) => async (t) => {
      try {
        utils.chdirWorkspaces();
        const spyPlugin = sinon.spy(params.plugins, 'loadPlugin');
        t.teardown(spyPlugin.restore);

        const response = await params.cli.monitor('mono-repo-project', {
          json: true,
          allProjects: true,
        });
        JSON.parse(response).forEach((res) => {
          if (_.isObject(res)) {
            t.pass('monitor outputted JSON');
          } else {
            t.fail('Failed parsing monitor JSON output');
          }

          const keyList = [
            'packageManager',
            'manageUrl',
            'id',
            'projectName',
            'isMonitored',
          ];

          keyList.forEach((k) => {
            !_.get(res, k) ? t.fail(k + ' not found') : t.pass(k + ' found');
          });
        });
      } catch (error) {
        t.fail('should have passed', error);
      }
    },
    '`monitor maven-multi-app --all-projects --detection-depth=2 --exclude=simple-child`': (
      params,
      utils,
    ) => async (t) => {
      utils.chdirWorkspaces();
      const spyPlugin = sinon.spy(params.plugins, 'loadPlugin');
      t.teardown(spyPlugin.restore);
      const result = await params.cli.monitor('maven-multi-app', {
        allProjects: true,
        detectionDepth: 2,
        exclude: 'simple-child',
      });
      t.ok(
        spyPlugin.withArgs('rubygems').notCalled,
        'did not call rubygems plugin',
      );
      t.ok(spyPlugin.withArgs('npm').notCalled, 'did not call npm plugin');
      t.equals(
        spyPlugin.withArgs('maven').callCount,
        1,
        'calls maven plugin once, excluding simple-child',
      );
      t.match(result, 'maven/some/project-id', 'maven project was monitored ');
      const request = params.server.popRequest();
      t.ok(request, 'Monitor POST request');
      t.match(request.url, '/monitor/', 'puts at correct url');
      t.notOk(request.body.targetFile, "doesn't send the targetFile");
      t.equal(request.method, 'PUT', 'makes PUT request');
      t.equal(
        request.headers['x-snyk-cli-version'],
        params.versionNumber,
        'sends version number',
      );
    },
    '`monitor monorepo-with-nuget with Cocoapods --all-projects and without same meta`': (
      params,
      utils,
    ) => async (t) => {
      utils.chdirWorkspaces();
      const spyPlugin = sinon.spy(params.plugins, 'loadPlugin');
      t.teardown(spyPlugin.restore);

      await params.cli.monitor('monorepo-with-nuget/src/cocoapods-app', {
        allProjects: true,
      });
      const cocoapodsAll = params.server.popRequest();
      // Cocoapods
      await params.cli.monitor('monorepo-with-nuget/src/cocoapods-app', {
        file: 'Podfile',
      });
      const requestsCocoapods = params.server.popRequest();
      t.deepEqual(
        cocoapodsAll.body,
        requestsCocoapods.body,
        'Same body for --all-projects and --file=src/cocoapods-app/Podfile',
      );
    },
    '`monitor mono-repo-go/hello-dep --all-projects sends same body as --file`': (
      params,
      utils,
    ) => async (t) => {
      utils.chdirWorkspaces();
      // mock plugin becuase CI tooling doesn't have go installed
      const mockPlugin = {
        async inspect() {
          return {
            plugin: {
              targetFile: 'Gopkg.lock',
              name: 'snyk-go-plugin',
              runtime: 'go',
            },
            package: {},
          };
        },
      };
      const loadPlugin = sinon.stub(params.plugins, 'loadPlugin');
      t.teardown(loadPlugin.restore);
      loadPlugin.withArgs('golangdep').returns(mockPlugin);
      await params.cli.monitor('mono-repo-go/hello-dep', {
        allProjects: true,
      });
      const allProjectsBody = params.server.popRequest();
      await params.cli.monitor('mono-repo-go/hello-dep', {
        file: 'Gopkg.lock',
      });
      const fileBody = params.server.popRequest();
      t.same(
        allProjectsBody.body,
        fileBody.body,
        'Same body for --all-projects and --file=mono-repo-go/hello-dep/Gopkg.lock',
      );
    },
    '`monitor mono-repo-go/hello-mod --all-projects sends same body as --file`': (
      params,
      utils,
    ) => async (t) => {
      utils.chdirWorkspaces();
      // mock plugin becuase CI tooling doesn't have go installed
      const mockPlugin = {
        async inspect() {
          return {
            plugin: {
              targetFile: 'go.mod',
              name: 'snyk-go-plugin',
              runtime: 'go',
            },
            package: {},
          };
        },
      };
      const loadPlugin = sinon.stub(params.plugins, 'loadPlugin');
      t.teardown(loadPlugin.restore);
      loadPlugin.withArgs('gomodules').returns(mockPlugin);
      await params.cli.monitor('mono-repo-go/hello-mod', {
        allProjects: true,
      });
      const allProjectsBody = params.server.popRequest();
      await params.cli.monitor('mono-repo-go/hello-mod', {
        file: 'go.mod',
      });
      const fileBody = params.server.popRequest();
      t.same(
        allProjectsBody.body,
        fileBody.body,
        'Same body for --all-projects and --file=mono-repo-go/hello-mod/go.mod',
      );
    },
    '`monitor mono-repo-go/hello-vendor --all-projects sends same body as --file`': (
      params,
      utils,
    ) => async (t) => {
      utils.chdirWorkspaces();
      // mock plugin becuase CI tooling doesn't have go installed
      const mockPlugin = {
        async inspect() {
          return {
            plugin: {
              targetFile: 'vendor/vendor.json',
              name: 'snyk-go-plugin',
              runtime: 'go',
            },
            package: {},
          };
        },
      };
      const loadPlugin = sinon.stub(params.plugins, 'loadPlugin');
      t.teardown(loadPlugin.restore);
      loadPlugin.withArgs('govendor').returns(mockPlugin);
      await params.cli.monitor('mono-repo-go/hello-vendor', {
        allProjects: true,
      });
      const allProjectsBody = params.server.popRequest();
      await params.cli.monitor('mono-repo-go/hello-vendor', {
        file: 'vendor/vendor.json',
      });
      const fileBody = params.server.popRequest();
      t.same(
        allProjectsBody.body,
        fileBody.body,
        'Same body for --all-projects and --file=mono-repo-go/hello-vendor/vendor/vendor.json',
      );
    },

    '`monitor mono-repo-go with --all-projects and --detectin-depth=3`': (
      params,
      utils,
    ) => async (t) => {
      utils.chdirWorkspaces();
      // mock plugin becuase CI tooling doesn't have go installed
      const mockPlugin = {
        async inspect() {
          return {
            plugin: {
              name: 'mock',
            },
            package: {},
          };
        },
      };
      const loadPlugin = sinon.stub(params.plugins, 'loadPlugin');
      t.teardown(loadPlugin.restore);
      loadPlugin.withArgs('golangdep').returns(mockPlugin);
      loadPlugin.withArgs('gomodules').returns(mockPlugin);
      loadPlugin.withArgs('govendor').returns(mockPlugin);
      loadPlugin.callThrough(); // don't mock npm plugin
      const result = await params.cli.monitor('mono-repo-go', {
        allProjects: true,
        detectionDepth: 3,
      });
      t.match(result, 'golangdep/some/project-id', 'dep project was monitored');
      t.match(result, 'gomodules/some/project-id', 'mod project was monitored');
      t.match(result, 'npm/graph/some/project-id', 'npm project was monitored');
      t.match(
        result,
        'govendor/some/project-id',
        'vendor project was monitored',
      );
      // Pop one extra call to server and filter out call to `featureFlag` endpoint
      const requests = params.server
        .popRequests(5)
        .filter((req) => req.url.includes('/monitor/'));
      t.equal(requests.length, 4, 'Correct amount of monitor requests');

      requests.forEach((req) => {
        t.match(req.url, '/monitor/', 'puts at correct url');
        t.notOk(req.body.targetFile, "doesn't send the targetFile");
        t.equal(req.method, 'PUT', 'makes PUT request');
        t.equal(
          req.headers['x-snyk-cli-version'],
          params.versionNumber,
          'sends version number',
        );
      });
    },
  },
};
