# App captures

The PNGs were captured from the built Mac app using only the synthetic fixtures in `examples/`. The operating system's top 28-pixel title-bar strip was omitted; the app content was preserved.

`walkthrough.gif` is a 30-second sequence of five actual screenshots, with pauses to read each step: empty Resolve screen, JSON input, analysis summary, recovered PNG details, and successful save. It is a screenshot walkthrough rather than a continuous screen recording. The saved PNG was opened by an image parser and its SHA-256 fingerprint checked against `examples/expected.json`.

`checksum.png` and `zip-password.png` show the upcoming desktop controls in the development source after v0.3.0. No production data or real credentials were used.
