rule Webshell_Txt_aspxlcx_RID2F48 : CHINA DEMO FILE T1505_003 WEBSHELL {
   meta:
      description = "Chinese Hacktool Set - Webshells - file aspxlcx.txt"
      author = "Florian Roth"
      reference = "http://tools.zjqhr.com/"
      date = "2015-06-14 11:50:31"
      score = 60
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      
      tags = "CHINA, DEMO, FILE, T1505_003, WEBSHELL"
      minimum_yara = "3.5.0"
      
   strings:
      $s1 = "public string remoteip = " ascii
      $s2 = "=Dns.Resolve(host);" ascii
      $s3 = "public string remoteport = " ascii
      $s4 = "public class PortForward" ascii
   condition: 
      uint16 ( 0 ) == 0x253c and filesize < 18KB and all of them
}