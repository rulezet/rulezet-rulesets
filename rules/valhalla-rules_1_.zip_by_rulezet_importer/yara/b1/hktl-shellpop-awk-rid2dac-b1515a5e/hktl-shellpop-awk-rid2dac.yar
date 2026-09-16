rule HKTL_shellpop_awk_RID2DAC : DEMO HKTL {
   meta:
      description = "Detects suspicious AWK Shellpop"
      author = "Tobias Michalski"
      reference = "https://github.com/0x00-0x00/ShellPop"
      date = "2018-05-18 10:41:51"
      score = 75
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      hash1 = "7513a0a0ba786b0e22a9a7413491b4011f60af11253c596fa6857fb92a6736fc"
      tags = "DEMO, HKTL"
      minimum_yara = "3.5.0"
      
   strings:
      $s1 = "awk 'BEGIN {s = \"/inet/tcp/0/" ascii
      $s2 = "; while(42) " ascii
   condition: 
      filesize < 1KB and 1 of them
}