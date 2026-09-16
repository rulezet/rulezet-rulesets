rule OpCloudHopper_WindowXarBot_RID315C : APT DEMO EXE FILE {
   meta:
      description = "Malware related to Operation Cloud Hopper"
      author = "Florian Roth"
      reference = "https://www.pwc.co.uk/cyber-security/pdf/cloud-hopper-annex-b-final.pdf"
      date = "2017-04-07 13:19:11"
      score = 75
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      
      tags = "APT, DEMO, EXE, FILE"
      minimum_yara = "3.5.0"
      
   strings:
      $s1 = "\\Release\\WindowXarbot.pdb" ascii
   condition: 
      ( uint16 ( 0 ) == 0x5a4d and filesize < 2000KB and all of them )
}