rule DarkEYEv3_Cryptor_RID2D71 : DEMO EXE FILE SUSP {
   meta:
      description = "Rule to detect DarkEYEv3 encrypted executables (often malware)"
      author = "Florian Roth"
      reference = "http://darkeyev3.blogspot.fi/"
      date = "2015-05-24 10:32:01"
      score = 55
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      hash1 = "d53149968eca654fc0e803f925e7526fdac2786c"
      hash2 = "7e3a8940d446c57504d6a7edb6445681cca31c65"
      hash3 = "d3dd665dd77b02d7024ac16eb0949f4f598299e7"
      tags = "DEMO, EXE, FILE, SUSP"
      minimum_yara = "3.5.0"
      
   strings:
      $s0 = "\\DarkEYEV3-" 
   condition: 
      uint16 ( 0 ) == 0x5a4d and $s0
}