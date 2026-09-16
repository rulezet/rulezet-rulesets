rule APT_HAFNIUM_Forensic_Artefacts_Mar21_1_RID3463 : APT DEMO G0125 {
   meta:
      description = "Detects forensic artefacts found in HAFNIUM intrusions"
      author = "Florian Roth"
      reference = "https://www.microsoft.com/security/blog/2021/03/02/hafnium-targeting-exchange-servers/"
      date = "2021-03-02 15:28:21"
      score = 75
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      
      tags = "APT, DEMO, G0125"
      minimum_yara = "3.5.0"
      
   strings:
      $s1 = "lsass.exe C:\\windows\\temp\\lsass" ascii wide fullword
      $s2 = "c:\\ProgramData\\it.zip" ascii wide fullword
      $s3 = "powercat.ps1'); powercat -c" ascii wide fullword
   condition: 
      1 of them
}