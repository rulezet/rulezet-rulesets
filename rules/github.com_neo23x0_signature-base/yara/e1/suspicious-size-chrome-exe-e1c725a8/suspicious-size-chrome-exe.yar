rule Suspicious_Size_chrome_exe {
   meta:
      description = "Detects uncommon file size of chrome.exe"
      author = "Florian Roth (Nextron Systems)"
      score = 60
      nodeepdive = 1
      date = "2015-12-21"
      modified = "2022-09-15"
      noarchivescan = 1
      id = "f164394a-5c02-5056-aceb-044ee118578d"
   strings:
      $fp1 = "HP Sure Click Chromium Launcher" wide
      $fp2 = "BrChromiumLauncher.exe" wide fullword
   condition:
      uint16(0) == 0x5a4d
      and filename == "chrome.exe"
      and (filesize < 500KB or filesize > 5000KB)
      and not 1 of ($fp*)
}