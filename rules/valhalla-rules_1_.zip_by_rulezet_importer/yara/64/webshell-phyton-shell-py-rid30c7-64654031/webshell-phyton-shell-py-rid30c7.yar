rule Webshell_Phyton_Shell_py_RID30C7 : DEMO SCRIPT T1505_003 WEBSHELL {
   meta:
      description = "Semi-Auto-generated - file Phyton Shell.py.txt"
      author = "Florian Roth"
      reference = "-"
      date = "2014-03-29 12:54:21"
      score = 75
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      
      tags = "DEMO, SCRIPT, T1505_003, WEBSHELL"
      minimum_yara = "3.5.0"
      
   strings:
      $s1 = "sh_out=os.popen(SHELL+\" \"+cmd).readlines()" fullword
      $s2 = "#   d00r.py 0.3a (reverse|bind)-shell in python by fQ" fullword
      $s3 = "print \"error; help: head -n 16 d00r.py\"" fullword
      $s4 = "print \"PW:\",PW,\"PORT:\",PORT,\"HOST:\",HOST" fullword
   condition: 
      1 of them
}