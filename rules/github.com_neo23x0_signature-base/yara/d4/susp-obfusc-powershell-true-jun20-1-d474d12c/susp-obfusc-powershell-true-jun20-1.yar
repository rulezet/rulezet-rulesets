rule SUSP_OBFUSC_PowerShell_True_Jun20_1 {
   meta:
      description = "Detects indicators often found in obfuscated PowerShell scripts. Note: This detection is based on common characteristics typically associated with the mentioned threats, must be considered a clue and does not conclusively prove maliciousness."
      author = "Florian Roth (Nextron Systems)"
      reference = "https://github.com/corneacristian/mimikatz-bypass/"
      date = "2020-06-27"
      score = 75
      id = "e9bb870b-ad72-57d3-beff-2f84a81490eb"
   strings:
      $ = "${t`rue}" ascii nocase
      $ = "${tr`ue}" ascii nocase
      $ = "${tru`e}" ascii nocase
      $ = "${t`ru`e}" ascii nocase
      $ = "${tr`u`e}" ascii nocase
      $ = "${t`r`ue}" ascii nocase
      $ = "${t`r`u`e}" ascii nocase
   condition:
      filesize < 6000KB and 1 of them
}