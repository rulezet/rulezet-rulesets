rule Dubnium_Sample_2_RID2D37 : DEMO EXE FILE G0012 MAL {
   meta:
      description = "Detects sample mentioned in the Dubnium Report"
      author = "Florian Roth"
      reference = "https://www.microsoft.com/security/blog/2016/06/09/reverse-engineering-dubnium-2?source=mmpc"
      date = "2016-06-10 10:22:21"
      score = 75
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      modified = "2024-07-19"
      hash1 = "5246899b8c74a681e385cbc1dd556f9c73cf55f2a0074c389b3bf823bfc6ce4b"
      tags = "DEMO, EXE, FILE, G0012, MAL"
      minimum_yara = "3.5.0"
      
   strings:
      $x1 = ":*:::D:\\:c:~:" fullword ascii
      $s2 = "SPMUVR" fullword ascii
   condition: 
      ( uint16 ( 0 ) == 0x5a4d and filesize < 2000KB and all of them )
}