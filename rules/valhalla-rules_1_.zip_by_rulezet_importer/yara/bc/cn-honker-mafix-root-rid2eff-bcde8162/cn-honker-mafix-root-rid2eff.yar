rule CN_Honker_mafix_root_RID2EFF : CHINA DEMO SCRIPT SUSP {
   meta:
      description = "Script from disclosed CN Honker Pentest Toolset - file root"
      author = "Florian Roth"
      reference = "Disclosed CN Honker Pentest Toolset"
      date = "2015-06-23 11:38:21"
      score = 70
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      
      tags = "CHINA, DEMO, SCRIPT, SUSP"
      minimum_yara = "3.5.0"
      
   strings:
      $s0 = "echo \"# vbox (voice box) getty\" >> /tmp/.init1" fullword ascii
      $s1 = "cp /var/log/tcp.log $HOMEDIR/.owned/bex2/snifflog" fullword ascii
      $s2 = "if [ -f /sbin/xlogin ]; then" fullword ascii
   condition: 
      filesize < 96KB and all of them
}