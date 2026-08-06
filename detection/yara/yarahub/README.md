# YARAhub submission copies

**Upload the files from *this* directory, not from `../`.**

The rules one level up are the working copies. They are identical in logic but carry no
`yarahub_*` meta fields, so YARAhub rejects them with:

    Error: Missing field yarahub_reference_md5 in your YARA rule meta section

Same filenames, different directory — which is exactly how that mistake happens.

## Regenerating

```sh
python3 tools/prepare_yarahub.py --sample <reference-file> --rule detection/yara/<name>.yar
```

The script verifies that the rule actually matches the reference file before writing, and
derives `yarahub_uuid` deterministically from the rule name. Re-running it therefore
updates the existing YARAhub entry instead of creating a duplicate — which also means you
can re-upload a rule to correct its metadata.

## Do not edit these by hand

They are generated. Edit the working copy in `../`, then regenerate.
