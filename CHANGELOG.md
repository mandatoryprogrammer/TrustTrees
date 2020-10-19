# What's New

Thanks to all our contributors, users, and the many people that make `TrustTrees` possible! :heart:

If you love `TrustTrees`, please star our project on GitHub to show your support! :star:

<!--
# A.B.C
##### MMM DD(th|rd), YYYY

#### :newspaper: News
#### :mega: Release Highlights
#### :boom: Breaking Changes
#### :tada: New Features
#### :sparkles: Usability
#### :mortar_board: Walkthrough / Help
#### :performing_arts: Performance
#### :telescope: Accuracy
#### :bug: Bugfixes
#### :snake: Miscellaneous
#### :art: Display Changes

[#xxxx]: https://github.com/mandatoryprogrammer/TrustTrees/pull/xxxx
[@xxxx]: https://github.com/xxxx
-->

### v3.0.3
##### October 19th, 2020

#### :tada: New Features

- Added the ability to ask [DNSimple](https://dnsimple.com/) for domain availability ([#37], thanks [@tanx16])

[#37]: https://github.com/mandatoryprogrammer/TrustTrees/pull/37



### v3.0.2
##### July 4th, 2020

#### :bug: Bugfixes

- [Fixed bug where we were calling `open` on Linux](https://github.com/mandatoryprogrammer/TrustTrees/commit/5d2d267f72cd99db25cf464caac7c484ac33d2a3) (thanks [@dgzlopes])

[@dgzlopes]: https://github.com/dgzlopes



### v3.0.1
##### July 4th, 2020

#### :bug: Bugfixes

- [Fixed `ModuleNotFoundError` thrown when TrustTrees was not installed from source](https://github.com/mandatoryprogrammer/TrustTrees/commit/15e2856505bd36f2a52992c59d4e497e8f291566) (thanks [@Popyllol])
- Fixed missing `json` import in `draw.py` ([#34], thanks [@cclauss])

#### :snake: Miscellaneous
- Added GitHub Action to lint Python ([#35], thanks [@cclauss])

[@Popyllol]: https://github.com/Popyllol
[#34]: https://github.com/mandatoryprogrammer/TrustTrees/pull/34
[#35]: https://github.com/mandatoryprogrammer/TrustTrees/pull/35



### v3.0.0
##### January 8th, 2020

#### :tada: New Features

- Added the ability to ask [Route53 for domain availability](https://boto3.amazonaws.com/v1/documentation/api/latest/reference/services/route53domains.html#Route53Domains.Client.check_domain_availability) with AWS credentials ([#18], thanks [@tanx16])
- Added the ability to upload images to S3 ([#23], thanks [@tanx16])

#### :snake: Miscellaneous

- Various code quality improvements ([#24]/[#25]/[#26]/[#27]/[#28] thanks [@alanyee])

[#18]: https://github.com/mandatoryprogrammer/TrustTrees/pull/18
[#23]: https://github.com/mandatoryprogrammer/TrustTrees/pull/23
[#24]: https://github.com/mandatoryprogrammer/TrustTrees/pull/24
[#25]: https://github.com/mandatoryprogrammer/TrustTrees/pull/25
[#26]: https://github.com/mandatoryprogrammer/TrustTrees/pull/26
[#27]: https://github.com/mandatoryprogrammer/TrustTrees/pull/27
[#28]: https://github.com/mandatoryprogrammer/TrustTrees/pull/28



### v2.0.1
##### July 26th, 2019

#### :tada: New Features

- [Added a new `-l`/`--target-list` option](https://github.com/mandatoryprogrammer/TrustTrees/commit/b3dc983e642e0a47d28de6161a61a8706f18bf34) (thanks [@AlexeyStolyarov] and [@thefinn93])

[@thefinn93]: https://github.com/thefinn93



### v2.0.0
##### July 25th, 2019

#### :tada: New Features

- [Added support for Gandi API V5 keys](https://github.com/mandatoryprogrammer/TrustTrees/commit/76e5813c1f9d2baa39e4a6fd78e2c60073d2e87e) (thanks [@robdollard], [@kalou] and [@davidnewhall])

#### :boom: Breaking Changes

- [Replaced the `--domain-check` option with `--gandi-api-v4-key`](https://github.com/mandatoryprogrammer/TrustTrees/commit/76e5813c1f9d2baa39e4a6fd78e2c60073d2e87e)

#### :snake: Miscellaneous

- Refactored `trusttrees.py` ([#13])

[#13]: https://github.com/mandatoryprogrammer/TrustTrees/pull/13
[@robdollard]: https://github.com/robdollard
[@kalou]: https://github.com/kalou
[@davidnewhall]: https://github.com/davidnewhall



### v1.0.0
##### July 24th, 2019

#### :mega: Release Highlights

- First version release



# Special thanks to our awesome contributors! :clap:

- [@alanyee]
- [@alexmerkel]
- [@AlexeyStolyarov]
- [@cclauss]
- [@iepathos]
- [@tanx16]
- [@zard777]

[@alanyee]: https://github.com/alanyee
[@alexmerkel]: https://github.com/alexmerkel
[@AlexeyStolyarov]: https://github.com/AlexeyStolyarov
[@cclauss]: https://github.com/cclauss
[@iepathos]: https://github.com/iepathos
[@tanx16]: https://github.com/tanx16
[@zard777]: https://github.com/zard777
