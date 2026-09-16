rule JSP_Browser_APT_webshell_RID303A : APT DEMO SCRIPT T1505_003 WEBSHELL {
   meta:
      description = "VonLoesch JSP Browser used as web shell by APT groups - jsp File browser 1.1a"
      author = "Florian Roth"
      reference = "-"
      date = "2014-10-10 12:30:51"
      score = 60
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      
      tags = "APT, DEMO, SCRIPT, T1505_003, WEBSHELL"
      minimum_yara = "3.5.0"
      
   strings:
      $a1a = "private static final String[] COMMAND_INTERPRETER = {\"" ascii
      $a1b = "cmd\", \"/C\"}; // Dos,Windows" ascii
      $a2 = "Process ls_proc = Runtime.getRuntime().exec(comm, null, new File(dir));" ascii
      $a3 = "ret.append(\"!!!! Process has timed out, destroyed !!!!!\");" ascii
   condition: 
      all of them
}