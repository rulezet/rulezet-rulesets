rule HawkEye_Keylogger_Feb18_1_RID302C : DEMO EXE FILE MAL T1056_001 {
   meta:
      description = "Semiautomatically generated YARA rule"
      author = "Florian Roth"
      reference = "https://app.any.run/tasks/ae2521dd-61aa-4bc7-b0d8-8c85ddcbfcc9"
      date = "2018-02-12 12:28:31"
      score = 90
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      modified = "2023-01-06"
      hash1 = "bb58922ad8d4a638e9d26076183de27fb39ace68aa7f73adc0da513ab66dc6fa"
      tags = "DEMO, EXE, FILE, MAL, T1056_001"
      minimum_yara = "3.5.0"
      
   strings:
      $s1 = "UploadReportLogin.asmx" fullword wide
      $s2 = "tmp.exe" fullword wide
      $s3 = "%appdata%\\" wide
   condition: 
      uint16 ( 0 ) == 0x5a4d and filesize < 2000KB and all of them
}