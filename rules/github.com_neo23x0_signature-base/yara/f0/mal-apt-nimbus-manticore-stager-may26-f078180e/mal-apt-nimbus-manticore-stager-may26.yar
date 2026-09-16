rule MAL_APT_Nimbus_Manticore_Stager_May26 {
   meta:
      description = "Detects .NET based stager using AppDomain Hijacking observed to be used by Nimbus Manticore (UNC1549). The stager drops another payload and establishes persistence via scheduled task."
      author = "Jonathan Peters (Nextron Systems)"
      date = "2026-05-20"
      reference = "https://www.nextron-systems.com/2026/06/01/detecting-nimbus-manticore-and-their-sideloading-infection-chains/"
      hash = "eee657ffdb2af8ed6412221e7d5fbf4f5742f2ac2c88f43f12db46af0697de71"
      score = 80
   strings:
      $x1 = "MyCompany-Product-TOTP-Salt-2024!@#$" wide fullword
      $x2 = "TOTPGuardRunner" ascii fullword
      $x3 = "\\AppDomainInjection-metlifeScenario\\TOTP" ascii

      $sa1 = "EncData" ascii fullword
      $sa2 = "DecryptAndSaveToDesktop" ascii fullword
      $sa3 = "CopyHelloToDesktop" ascii fullword

      $sb1 = "doit" wide fullword
      $sb2 = "DailyTrigger" wide fullword
      $sb3 = "GetTypeFromCLSID" ascii
      $sb4 = "yyyy-MM-ddTHH:mm:ss" wide fullword
   condition:
      uint16(0) == 0x5a4d
      and
      (
         1 of ($x*)
         or all of ($sa*)
         or all of ($sb*)
      )
}