rule APT_PS1_SysAid_EXPL_ForensicArtifacts_Nov23_1_RID372D : APT CVE_2023_47246 DEMO EXPLOIT SCRIPT T1059_001 {
   meta:
      description = "Detects forensic artifacts found in attacks on SysAid on-prem software exploiting CVE-2023-47246"
      author = "Florian Roth"
      reference = "https://www.sysaid.com/blog/service-desk/on-premise-software-security-vulnerability-notification"
      date = "2023-11-09 17:27:21"
      score = 85
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      
      tags = "APT, CVE_2023_47246, DEMO, EXPLOIT, SCRIPT, T1059_001"
      minimum_yara = "3.5.0"
      
   strings:
      $x1 = "if ($s -match '^(Sophos).*\\.exe\\s') {echo $s; $bp++;}" ascii wide
      $x2 = "$s=$env:SehCore;$env:SehCore=\"\";Invoke-Expression $s;" ascii wide
   condition: 
      1 of them
}