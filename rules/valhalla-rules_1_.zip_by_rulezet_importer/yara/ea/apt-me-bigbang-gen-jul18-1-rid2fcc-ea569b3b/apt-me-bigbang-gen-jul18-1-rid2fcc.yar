import "pe"
rule APT_ME_BigBang_Gen_Jul18_1_RID2FCC : APT DEMO EXE FILE G1028 GEN MIDDLE_EAST {
   meta:
      description = "Detects malware from Big Bang campaign against Palestinian authorities"
      author = "Florian Roth"
      reference = "https://research.checkpoint.com/apt-attack-middle-east-big-bang/"
      date = "2018-07-09 12:12:31"
      score = 75
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      hash1 = "4db68522600f2d8aabd255e2da999a9d9c9f1f18491cfce9dadf2296269a172b"
      hash2 = "ac6462e9e26362f711783b9874d46fefce198c4c3ca947a5d4df7842a6c51224"
      hash3 = "e1f52ea30d25289f7a4a5c9d15be97c8a4dfe10eb68ac9d031edcc7275c23dbc"
      tags = "APT, DEMO, EXE, FILE, G1028, GEN, MIDDLE_EAST"
      required_modules = "pe"
      minimum_yara = "3.5.0"
      
   strings:
      $x2 = "%@W@%S@c@ri%@p@%t.S@%he@%l%@l" ascii
      $x3 = "S%@h%@e%l%@l." ascii
      $x4 = "(\"S@%t@%a%@rt%@up\")" ascii
      $x5 = "aW5zdGFsbCBwcm9nOiBwcm9nIHdpbGwgZGVsZXRlIG9sZCB0bXAgZmlsZQ==" fullword ascii
      $x6 = "aW5zdGFsbCBwcm9nOiBUaGVyZSBpcyBubyBvbGQgZmlsZSBpbiB0ZW1wLg==" fullword ascii
      $x7 = "VXBkYXRlIHByb2c6IFRoZXJlIGlzIG5vIG9sZCBmaWxlIGluIHRlbXAu" fullword ascii
      $x8 = "aW5zdGFsbCBwcm9nOiBDcmVhdGUgVGFzayBhZnRlciA1IG1pbiB0byBydW4gRmlsZSBmcm9tIHRtcA==" fullword ascii
      $x9 = "UnVuIEZpbGU6IE15IHByb2cgaXMgRXhpdC4=" fullword ascii
      $x10 = "li%@%@nk.W%@%@indo@%%@%@%wS%@%@tyle = 3" fullword ascii
   condition: 
      uint16 ( 0 ) == 0x5a4d and filesize < 3000KB and ( 1 of them or pe.imphash ( ) == "0f09ea2a68d04f331df9a5d0f8641332" )
}