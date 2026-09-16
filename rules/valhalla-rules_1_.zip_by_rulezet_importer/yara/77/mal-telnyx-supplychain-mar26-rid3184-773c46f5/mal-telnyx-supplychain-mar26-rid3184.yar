rule MAL_Telnyx_SupplyChain_Mar26_RID3184 : DEMO MAL {
   meta:
      description = "Detects malicious indicators used in Telnyx supply chain attack"
      author = "Marius Benthin"
      reference = "https://www.aikido.dev/blog/telnyx-pypi-compromised-teampcp-canisterworm"
      date = "2026-03-28 13:25:51"
      score = 80
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      
      tags = "DEMO, MAL"
      minimum_yara = "3.5.0"
      
   strings:
      $s1 = "bXNidWlsZC5leGU=" 
      $s2 = "TW96aWxsY" 
      $s3 = ".getnframes(" 
      $s4 = "exec(base64.b64decode(" 
   condition: 
      filesize < 500KB and 3 of them
}