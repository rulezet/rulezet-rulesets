rule EquationGroup_morerats_client_genkey_RID35F0 : APT DEMO G0020 {
   meta:
      description = "Equation Group hack tool set"
      author = "Florian Roth"
      reference = "https://medium.com/@shadowbrokerss/dont-forget-your-base-867d304a94b1"
      date = "2017-04-09 16:34:31"
      score = 75
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      hash1 = "0ce455fb7f46e54a5db9bef85df1087ff14d2fc60a88f2becd5badb9c7fe3e89"
      tags = "APT, DEMO, G0020"
      minimum_yara = "3.5.0"
      
   strings:
      $x1 = "rsakey_txt = lo_execute('openssl genrsa 2048 2> /dev/null | openssl rsa -text 2> /dev/null')" fullword ascii
      $x2 = "client_auth = binascii.hexlify(lo_execute('openssl rand 16'))" fullword ascii
   condition: 
      ( filesize < 3KB and all of them )
}