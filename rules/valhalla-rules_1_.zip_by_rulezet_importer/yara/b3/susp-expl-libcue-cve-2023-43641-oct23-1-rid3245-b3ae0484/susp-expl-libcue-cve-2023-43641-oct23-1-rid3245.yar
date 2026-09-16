rule SUSP_EXPL_LIBCUE_CVE_2023_43641_Oct23_1_RID3245 : CVE_2023_43641 DEMO EXPLOIT SUSP {
   meta:
      description = "Detects a suspicious .cue file that could be an exploitation attempt of libcue vulnerability CVE-2023-43641"
      author = "Florian Roth"
      reference = "https://github.com/github/securitylab/blob/main/SecurityExploits/libcue/track_set_index_CVE-2023-43641/README.md"
      date = "2023-10-27 13:58:01"
      score = 70
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      
      tags = "CVE_2023_43641, DEMO, EXPLOIT, SUSP"
      minimum_yara = "3.5.0"
      
   strings:
      $a1 = "TRACK " 
      $a2 = "FILE " 
      $s1 = "INDEX 4294" 
   condition: 
      filesize < 100KB and all of them
}