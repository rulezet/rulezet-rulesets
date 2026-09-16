rule SUSP_Recon_Outputs_Jun20_1 {
   meta:
      description = "Detects outputs of many different commands often used for reconnaissance purposes"
      author = "Florian Roth (Nextron Systems)"
      reference = "https://securelist.com/cycldek-bridging-the-air-gap/97157/"
      date = "2020-06-04"
      score = 60
      id = "ec3759aa-212f-52ce-9f38-636accd35749"
   strings:
      
      $s1 = ". . . . : Yes" ascii 
      
      $s2 = "with 32 bytes of data:" ascii
      
      $s3 = "ff-ff-ff-ff-ff-ff     static" ascii
       
      $s4 = "  TCP    0.0.0.0:445" ascii 
       
      $s5 = "System Idle Process" ascii
   condition:
      filesize < 150KB and
      4 of them
}