rule Dubnium_Sample_1_RID2D36 : DEMO EXE FILE G0012 MAL {
   meta:
      description = "Detects sample mentioned in the Dubnium Report"
      author = "Florian Roth"
      reference = "https://www.microsoft.com/security/blog/2016/06/09/reverse-engineering-dubnium-2?source=mmpc"
      date = "2016-06-10 10:22:11"
      score = 75
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      modified = "2024-07-19"
      hash1 = "839baf85de657b6d6503b6f94054efa8841f667987a9c805eab94a85a859e1ba"
      tags = "DEMO, EXE, FILE, G0012, MAL"
      minimum_yara = "3.5.0"
      
   strings:
      $key1 = "3b840e20e9555e9fb031c4ba1f1747ce25cc1d0ff664be676b9b4a90641ff194" fullword ascii
      $key2 = "90631f686a8c3dbc0703ffa353bc1fdf35774568ac62406f98a13ed8f47595fd" fullword ascii
   condition: 
      uint16 ( 0 ) == 0x5a4d and filesize < 2000KB and all of them
}