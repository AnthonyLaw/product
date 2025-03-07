# Symbol Product Monorepo

In Q1 2022, we consolidated a number of projects into this repository.
It includes our optin manager.

| component | lint | build | test | coverage | package |
|-----------|------|-------|------|----------| ------- |
| [@optin/puller](optin/puller) | [![lint][optin-puller-lint]][optin-puller-job] || [![test][optin-puller-test]][optin-puller-job]| [![][optin-puller-cov]][optin-puller-cov-link] |

## Full Coverage Report

Detailed version can be seen on [codecov.io][product-cov-link].

[![][product-cov]][product-cov-link]

[product-cov]: https://codecov.io/gh/symbol/product/branch/dev/graphs/tree.svg
[product-cov-link]: https://codecov.io/gh/symbol/product/tree/dev

[optin-puller-job]: https://jenkins.symboldev.com/blue/organizations/jenkins/Symbol%2Fgenerated%2Fproduct%2Fpuller/activity?branch=dev
[optin-puller-lint]: https://jenkins.symboldev.com/buildStatus/icon?job=Symbol%2Fgenerated%2Fproduct%2Fpuller%2Fdev%2F&config=optin-puller-lint
[optin-puller-test]: https://jenkins.symboldev.com/buildStatus/icon?job=Symbol%2Fgenerated%2Fproduct%2Fpuller%2Fdev%2F&config=optin-puller-test
[optin-puller-cov]: https://codecov.io/gh/symbol/product/branch/dev/graph/badge.svg?token=SSYYBMK0M7&flag=optin-puller
[optin-puller-cov-link]: https://codecov.io/gh/symbol/product/tree/dev/optin/puller
