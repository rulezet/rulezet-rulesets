rule SUSP_Doc_RTF_ExternalResource_May22_RID33F0 : CVE_2022_30190 DEMO FILE SUSP {
   meta:
      description = "Detects a suspicious pattern in RTF files which downloads external resources as seen in CVE-2022-30190 / Follina exploitation"
      author = "Tobias Michalski, Christian Burkard"
      reference = "https://doublepulsar.com/follina-a-microsoft-office-code-execution-vulnerability-1a47fce5629e"
      date = "2022-05-30 15:09:11"
      score = 70
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      modified = "2022-05-31"
      tags = "CVE_2022_30190, DEMO, FILE, SUSP"
      minimum_yara = "3.5.0"
      
   strings:
      $s1 = " LINK htmlfile \"http" ascii
      $s2 = ".html!\" " ascii
   condition: 
      uint32be ( 0 ) == 0x7B5C7274 and filesize < 300KB and all of them
}