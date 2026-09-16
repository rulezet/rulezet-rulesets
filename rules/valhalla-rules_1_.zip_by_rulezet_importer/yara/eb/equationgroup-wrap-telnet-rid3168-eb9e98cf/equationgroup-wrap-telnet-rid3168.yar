rule EquationGroup_wrap_telnet_RID3168 : APT DEMO FILE G0020 SCRIPT {
   meta:
      description = "Equation Group hack tool leaked by ShadowBrokers- file wrap-telnet.sh"
      author = "Florian Roth"
      reference = "https://medium.com/@shadowbrokerss/dont-forget-your-base-867d304a94b1"
      date = "2017-04-08 13:21:11"
      score = 75
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      hash1 = "4962b307a42ba18e987d82aa61eba15491898978d0e2f0e4beb02371bf0fd5b4"
      tags = "APT, DEMO, FILE, G0020, SCRIPT"
      minimum_yara = "3.5.0"
      
   strings:
      $s1 = "echo \"example: ${0} -l 192.168.1.1 -p 22222 -s 22223 -x 9999\"" fullword ascii
      $s2 = "-x [ port to start mini X server on DEFAULT = 12121 ]\"" fullword ascii
      $s3 = "echo \"Call back port2 = ${SPORT}\"" fullword ascii
   condition: 
      ( uint16 ( 0 ) == 0x2123 and filesize < 4KB and 1 of them )
}