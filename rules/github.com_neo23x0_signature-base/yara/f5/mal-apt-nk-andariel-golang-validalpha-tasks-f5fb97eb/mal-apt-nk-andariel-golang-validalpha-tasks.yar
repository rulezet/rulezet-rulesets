rule MAL_APT_NK_Andariel_GoLang_Validalpha_Tasks {
   meta:
      author = "CISA.gov"
      description = "Detects a variant of the GoLang Validalpha malware"
      reference = "https://www.cisa.gov/news-events/cybersecurity-advisories/aa24-207a"
      date = "2024-07-25"
      score = 80
      id = "caa67a79-3ea6-5910-971c-f311722570ff"
   strings:
      $ = "main.ScreenMonitThread"
      $ = "main.CmdShell"
      $ = "main.GetAllFoldersAndFiles"
      $ = "main.SelfDelete"
   condition:
      all of them
}