# Contributing

Please adhere to PEP 8 where appropriate. Code committed must be
submitted under the existing project license (MIT).

## Pull requests

Open pull requests against the **`main`** branch.

CI (tox via GitHub Actions) must pass for the supported Python versions
before merge.

## Security

Report vulnerabilities privately per [SECURITY.md](SECURITY.md). Do not
open public issues for security reports.

## Development

```bash
poetry install --with test,dev
poetry run tox
```

## OpenSSF Best Practices

This project aims to earn an
[OpenSSF Best Practices](https://www.bestpractices.dev/) badge.
Maintainers: create or update the project entry at
[bestpractices.dev](https://www.bestpractices.dev/en/projects/new)
(repo URL: `https://github.com/FirefighterBlu3/python-pam`), then add the
badge markdown to `README.md` using the assigned project ID.
