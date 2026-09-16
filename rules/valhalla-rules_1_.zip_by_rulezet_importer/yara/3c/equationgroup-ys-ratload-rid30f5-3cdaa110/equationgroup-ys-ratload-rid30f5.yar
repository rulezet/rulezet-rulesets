rule EquationGroup_ys_ratload_RID30F5 : APT DEMO FILE G0020 SCRIPT {
   meta:
      description = "Equation Group hack tool leaked by ShadowBrokers- file ys.ratload.sh"
      author = "Florian Roth"
      reference = "https://medium.com/@shadowbrokerss/dont-forget-your-base-867d304a94b1"
      date = "2017-04-08 13:02:01"
      score = 75
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      hash1 = "a340e5b5cfd41076bd4d6ad89d7157eeac264db97a9dddaae15d935937f10d75"
      tags = "APT, DEMO, FILE, G0020, SCRIPT"
      minimum_yara = "3.5.0"
      
   strings:
      $x1 = "echo \"example: ${0} -l 192.168.1.1 -p 22222 -x 9999\"" fullword ascii
      $x2 = "-x [ port to start mini X server on DEFAULT = 12121 ]\"" fullword ascii
      $x3 = "CALLBACK_PORT=32177" fullword ascii
   condition: 
      ( uint16 ( 0 ) == 0x2123 and filesize < 3KB and 1 of them )
}