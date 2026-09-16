rule Webshell_wh_bindshell_py_RID30E1 : DEMO SCRIPT T1505_003 WEBSHELL {
   meta:
      description = "Semi-Auto-generated - file wh_bindshell.py.txt"
      author = "Florian Roth"
      reference = "-"
      date = "2014-03-29 12:58:41"
      score = 75
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      
      tags = "DEMO, SCRIPT, T1505_003, WEBSHELL"
      minimum_yara = "3.5.0"
      
   strings:
      $s0 = "#Use: python wh_bindshell.py [port] [password]" 
      $s2 = "python -c\"import md5;x=md5.new('you_password');print x.hexdigest()\"" fullword
      $s3 = "#bugz: ctrl+c etc =script stoped=" fullword
   condition: 
      1 of them
}