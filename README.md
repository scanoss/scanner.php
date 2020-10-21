# scanner.php

Simple PHP implementation of a PHP-CLI scanner for the OSSKB (Open Source KB)

# Usage

```
php scanner.php PATH
```

# How does it work

This reference code illustrates the usage of the SCANOSS API to obtain identification against the OSSKB without sending the actual code, but instead the WFP hashes

Analyzed files are read into memory, WFP fingerprints are calculated and sent to the [OSSKB API](https://osskb.org)

Results are printed via STDOUT.

# License

scanner.php is released under the GPL 2.0 license. Please check the LICENSE file for further details.


