rule Webshell_cgi_python_py_RID3022 : DEMO SCRIPT T1059_006 T1505_003 WEBSHELL {
   meta:
      description = "Semi-Auto-generated - file cgi-python.py.txt"
      author = "Florian Roth"
      reference = "-"
      date = "2014-03-29 12:26:51"
      score = 75
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      
      tags = "DEMO, SCRIPT, T1059_006, T1505_003, WEBSHELL"
      minimum_yara = "3.5.0"
      
   strings:
      $s0 = "a CGI by Fuzzyman" 
      $s1 = "\"\"\"+fontline +\"Version : \" + versionstring + \"\"\", Running on : \"\"\" + " 
      $s2 = "values = map(lambda x: x.value, theform[field])     # allows for" 
   condition: 
      1 of them
}