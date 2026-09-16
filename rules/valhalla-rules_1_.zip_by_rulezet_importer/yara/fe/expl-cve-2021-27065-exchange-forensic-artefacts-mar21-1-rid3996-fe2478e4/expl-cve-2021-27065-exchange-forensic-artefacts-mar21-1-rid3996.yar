rule EXPL_CVE_2021_27065_Exchange_Forensic_Artefacts_Mar21_1_RID3996 : CVE_2021_27065 DEMO EXPLOIT G0125 SCRIPT {
   meta:
      description = "Detects forensic artefacts found in HAFNIUM intrusions exploiting CVE-2021-27065"
      author = "Florian Roth"
      reference = "https://www.volexity.com/blog/2021/03/02/active-exploitation-of-microsoft-exchange-zero-day-vulnerabilities/"
      date = "2021-03-02 19:10:11"
      score = 75
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      modified = "2023-12-01"
      tags = "CVE_2021_27065, DEMO, EXPLOIT, G0125, SCRIPT"
      minimum_yara = "3.5.0"
      
   strings:
      $s1 = "S:CMD=Set-OabVirtualDirectory.ExternalUrl='" ascii wide fullword
   condition: 
      1 of them
}