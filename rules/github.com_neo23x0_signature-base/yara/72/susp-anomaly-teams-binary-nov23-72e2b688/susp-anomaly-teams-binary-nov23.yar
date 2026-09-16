import "pe"
rule SUSP_ANOMALY_Teams_Binary_Nov23 : FILE {
   meta:
      description = "Detects a suspicious binary with the name teams.exe, update.exe or squirrel.exe in the AppData folder of Microsoft Teams that is unsigned or signed by a different CA"
      author = "Florian Roth"
      score = 60
      reference = "https://twitter.com/steve_noel/status/1722698479636476325/photo/1"
      date = "2023-11-11"
      modified = "2024-12-03"
      id = "60557ed1-ac16-5e3b-b105-157dc34f6ad7"
   strings:
      $a1 = "Microsoft Code Signing PCA" ascii
   condition:
      (
         filename iequals "teams.exe" or
         filename iequals "update.exe" or 
         filename iequals "squirrel.exe"
      )
      and filepath icontains "\\AppData\\Local\\Microsoft\\Teams"
      and pe.number_of_signatures == 0
      and not $a1
}