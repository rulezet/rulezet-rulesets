import "hash"
rule POC_secret_rule {
  meta:
    description = "POC: Detects hashed strings allowing to keep it secret, what the rule is actually looking for. This rule finds itself. Inspired by Solarwinds fnv1a hashed AV products."
    reference   = "https://yara.readthedocs.io/en/v4.2.0/modules/hash.html"
    license     = "Detection Rule License 1.1 https://github.com/SigmaHQ/Detection-Rule-License"
    author      = "Arnim Rupp"
    date        = "2023-02-13"

  strings:
    $public = "reference = \""

  condition:
    $public and
    filesize < 100KB and
        hash.md5(@public, 69) == "fcb7f398e250ba5f1a2d532df3a938b2"  }