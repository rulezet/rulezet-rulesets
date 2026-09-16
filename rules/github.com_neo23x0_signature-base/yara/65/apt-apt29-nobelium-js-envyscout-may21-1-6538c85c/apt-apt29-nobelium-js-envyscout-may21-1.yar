rule APT_APT29_NOBELIUM_JS_EnvyScout_May21_1 {
   meta:
      description = "Detects EnvyScout deobfuscator code as used by NOBELIUM group"
      author = "Florian Roth (Nextron Systems)"
      reference = "https://www.microsoft.com/security/blog/2021/05/28/breaking-down-nobeliums-latest-early-stage-toolset/"
      date = "2021-05-29"
      id = "42739aad-a88a-545b-8256-1f727c79c4f8"
   strings:
      $x1 = "[i].charCodeAt(0) ^ 2);}"
   condition:
      filesize < 5000KB and 1 of them
}