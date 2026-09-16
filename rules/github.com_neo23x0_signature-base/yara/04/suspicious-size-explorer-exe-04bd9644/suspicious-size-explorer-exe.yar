rule Suspicious_Size_explorer_exe {
   meta:
      description = "Detects uncommon file size of explorer.exe"
      license = "https://creativecommons.org/licenses/by-nc/4.0/"
      author = "Florian Roth (Nextron Systems)"
      score = 60
      nodeepdive = 1
      date = "2015-12-21"
      modified = "2022-04-27"
      noarchivescan = 1
      id = "408bdb95-3b15-5f4e-a948-949ea4ce0477"
   strings:
      $fp = "Wine placeholder DLL"
   condition:
      uint16(0) == 0x5a4d
      and filename == "explorer.exe"
      and not filepath contains "teamviewer"
      and not filepath contains "/lib/wine/fakedlls"
      and (filesize < 800KB or filesize > 6500KB)
      and not $fp
}