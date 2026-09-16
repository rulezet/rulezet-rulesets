rule BlackEnergy_Driver_USBMDM_RID304A : APT DEMO EXE FILE blackenergy {
   meta:
      description = "Semiautomatically generated YARA rule"
      author = "Florian Roth"
      reference = "http://www.welivesecurity.com/2016/01/03/blackenergy-sshbeardoor-details-2015-attacks-ukrainian-news-media-electric-industry/"
      date = "2016-01-04 12:33:31"
      score = 90
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      hash1 = "7874a10e551377d50264da5906dc07ec31b173dee18867f88ea556ad70d8f094"
      hash2 = "b73777469f939c331cbc1c9ad703f973d55851f3ad09282ab5b3546befa5b54a"
      hash3 = "edb16d3ccd50fc8f0f77d0875bf50a629fa38e5ba1b8eeefd54468df97eba281"
      tags = "APT, DEMO, EXE, FILE, blackenergy"
      minimum_yara = "3.5.0"
      
   strings:
      $s1 = "USB MDM Driver" fullword wide
      $s2 = "KdDebuggerNotPresent" fullword ascii
      $s3 = "KdDebuggerEnabled" fullword ascii
   condition: 
      uint16 ( 0 ) == 0x5a4d and filesize < 180KB and all of them
}