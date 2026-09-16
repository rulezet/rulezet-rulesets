rule MAL_APT_Nimbus_Manticore_Stager_May26_RID34B0 : APT DEMO EXE FILE MAL T1053_005 {
   meta:
      description = "Detects .NET based stager using AppDomain Hijacking observed to be used by Nimbus Manticore (UNC1549). The stager drops another payload and establishes persistence via scheduled task."
      author = "Jonathan Peters (cod3nym)"
      reference = "https://www.nextron-systems.com/2026/06/01/detecting-nimbus-manticore-and-their-sideloading-infection-chains"
      date = "2026-05-20 15:41:11"
      score = 80
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      
      tags = "APT, DEMO, EXE, FILE, MAL, T1053_005"
      minimum_yara = "3.5.0"
      
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
      uint16 ( 0 ) == 0x5a4d and ( 1 of ( $x* ) or all of ( $sa* ) or all of ( $sb* ) )
}