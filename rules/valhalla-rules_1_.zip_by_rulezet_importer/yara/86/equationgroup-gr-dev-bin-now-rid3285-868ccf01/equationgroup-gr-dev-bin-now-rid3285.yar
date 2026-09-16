rule EquationGroup_gr_dev_bin_now_RID3285 : APT DEMO G0020 {
   meta:
      description = "Equation Group hack tool set"
      author = "Florian Roth"
      reference = "https://medium.com/@shadowbrokerss/dont-forget-your-base-867d304a94b1"
      date = "2017-04-09 14:08:41"
      score = 75
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      hash1 = "f5ed8312fc6e624b04e1e2d6614f3c651c9e9902ff41f4d069c32caca0869fa4"
      tags = "APT, DEMO, G0020"
      minimum_yara = "3.5.0"
      
   strings:
      $x1 = "HTTP_REFERER=\"https://127.0.0.1:6655/cgi/redmin?op=cron&action=once\"" fullword ascii
      $x2 = "exec /usr/share/redmin/cgi/redmin" fullword ascii
   condition: 
      ( filesize < 1KB and 1 of them )
}