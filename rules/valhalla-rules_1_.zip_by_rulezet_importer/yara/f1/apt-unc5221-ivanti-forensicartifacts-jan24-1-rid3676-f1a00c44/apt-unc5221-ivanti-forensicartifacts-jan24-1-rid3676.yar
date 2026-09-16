rule APT_UNC5221_Ivanti_ForensicArtifacts_Jan24_1_RID3676 : APT DEMO {
   meta:
      description = "Detects forensic artifacts found in the Ivanti VPN exploitation campaign by APT UNC5221"
      author = "Florian Roth"
      reference = "https://www.mandiant.com/resources/blog/suspected-apt-targets-ivanti-zero-day"
      date = "2024-01-11 16:56:51"
      score = 75
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      
      tags = "APT, DEMO"
      minimum_yara = "3.5.0"
      
   strings:
      $x1 = "system(\"chmod a+x /home/etc/sql/dsserver/sessionserver.sh\");" 
      $x2 = "SSH-2.0-OpenSSH_0.3xx." 
      $x3 = "sed -i '/retval=$(exec $installer $@)/d' /pkg/do-install" 
   condition: 
      filesize < 5MB and 1 of them
}