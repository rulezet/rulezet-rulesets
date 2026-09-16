rule SUSP_AppDomainInjection_Keyword_May26 {
   meta:
      description = "Detects link files, archives and binaries that contain keywords related to AppDomain hijacking/injection a technique used by malware to sideload payloads."
      author = "Jonathan Peters (Nextron Systems)"
      date = "2026-05-27"
      reference = "https://attack.mitre.org/techniques/T1574/014/"
      hash = "eee657ffdb2af8ed6412221e7d5fbf4f5742f2ac2c88f43f12db46af0697de71"
      score = 70
   strings:
      $x1 = "AppDomainInjection" ascii wide fullword
      $x2 = "AppDomainHijack" ascii wide fullword
   condition:
      (
         uint16(0) == 0x5a4d          or uint16(0) == 0x4b50          or uint32(0x8000) == 0x30444301          or uint16(0) == 0x004c and uint32(4) == 0x00021401       )
      and 1 of ($x*)
}