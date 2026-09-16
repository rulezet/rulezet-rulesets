rule SUSP_Just_EICAR_RID2C24 : DEMO FILE SUSP {
   meta:
      description = "Just an EICAR test file - this is boring stuff"
      author = "Florian Roth"
      reference = "http://2016.eicar.org/85-0-Download.html"
      date = "2019-03-24 09:36:31"
      score = 40
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      hash1 = "275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f"
      tags = "DEMO, FILE, SUSP"
      minimum_yara = "3.5.0"
      
   strings:
      $s1 = "X5O!P%@AP[4\\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*" fullword ascii
   condition: 
      uint16 ( 0 ) == 0x3558 and filesize < 70 and $s1 at 0
}