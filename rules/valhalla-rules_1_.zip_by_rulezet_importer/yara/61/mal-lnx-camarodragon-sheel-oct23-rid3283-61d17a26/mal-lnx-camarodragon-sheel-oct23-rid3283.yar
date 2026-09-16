rule MAL_LNX_CamaroDragon_Sheel_Oct23_RID3283 : DEMO G0129 LINUX MAL {
   meta:
      description = "Detects CamaroDragon's tool named sheel"
      author = "Florian Roth"
      reference = "https://research.checkpoint.com/2023/the-dragon-who-sold-his-camaro-analyzing-custom-router-implant/"
      date = "2023-10-06 14:08:21"
      score = 85
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      hash1 = "7985f992dcc6fcce76ee2892700c8538af075bd991625156bf2482dbfebd5a5a"
      tags = "DEMO, G0129, LINUX, MAL"
      minimum_yara = "3.5.0"
      
   strings:
      $x1 = "-h server_ip -p server_port -i update_index[0-4] [-r]" ascii fullword
      $s1 = "read_ip" ascii fullword
      $s2 = "open fail.%m" ascii fullword
      $s3 = "ri:h:p:" ascii fullword
      $s4 = "update server list success!" ascii fullword
   condition: 
      uint16 ( 0 ) == 0x457f and filesize < 30KB and ( 1 of ( $x* ) or 3 of them ) or 4 of them
}