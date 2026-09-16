rule APT_RANSOM_Lockbit_ForensicArtifacts_Nov23_RID367C : APT DEMO LockBit RANSOM T1021_002 {
   meta:
      description = "Detects patterns found in Lockbit TA attacks exploiting Citrixbleed vulnerability CVE 2023-4966"
      author = "Florian Roth"
      reference = "https://www.cisa.gov/news-events/cybersecurity-advisories/aa23-325a"
      date = "2023-11-22 16:57:51"
      score = 75
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      
      tags = "APT, DEMO, LockBit, RANSOM, T1021_002"
      minimum_yara = "3.5.0"
      
   strings:
      $x1 = "taskkill /f /im sqlwriter.exe /im winmysqladmin.exe /im w3sqlmgr.exe" 
      $x2 = " 1> \\\\127.0.0.1\\admin$\\__" 
   condition: 
      1 of ( $x* )
}