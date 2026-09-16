rule MAL_Xbash_PY_Sep18_RID2D38 : DEMO FILE MAL SCRIPT {
   meta:
      description = "Detects Xbash malware"
      author = "Florian Roth"
      reference = "https://researchcenter.paloaltonetworks.com/2018/09/unit42-xbash-combines-botnet-ransomware-coinmining-worm-targets-linux-windows/"
      date = "2018-09-18 10:22:31"
      score = 75
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      hash1 = "7a18c7bdf0c504832c8552766dcfe0ba33dd5493daa3d9dbe9c985c1ce36e5aa"
      tags = "DEMO, FILE, MAL, SCRIPT"
      minimum_yara = "3.5.0"
      
   strings:
      $s1 = { 73 58 62 61 73 68 00 00 00 00 00 00 00 00 } 
   condition: 
      uint16 ( 0 ) == 0x457f and filesize < 10000KB and 1 of them
}