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

This project tracks an
[OpenSSF Best Practices](https://www.bestpractices.dev/projects/13794) badge
([project 13794](https://www.bestpractices.dev/projects/13794)).
Maintainers should keep the entry up to date as practices improve.
