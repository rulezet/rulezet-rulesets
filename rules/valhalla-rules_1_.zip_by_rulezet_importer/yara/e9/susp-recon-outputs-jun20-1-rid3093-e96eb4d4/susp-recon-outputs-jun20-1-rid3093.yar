rule SUSP_Recon_Outputs_Jun20_1_RID3093 : DEMO SUSP {
   meta:
      description = "Detects outputs of many different commands often used for reconnaissance purposes"
      author = "Florian Roth"
      reference = "https://securelist.com/cycldek-bridging-the-air-gap/97157/"
      date = "2020-06-04 12:45:41"
      score = 60
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      
      tags = "DEMO, SUSP"
      minimum_yara = "3.5.0"
      
   strings:
      $s1 = ". . . . : Yes" ascii
      $s2 = "with 32 bytes of data:" ascii
      $s3 = "ff-ff-ff-ff-ff-ff     static" ascii
      $s4 = "  TCP    0.0.0.0:445" ascii
      $s5 = "System Idle Process" ascii
   condition: 
      filesize < 150KB and 4 of them
}