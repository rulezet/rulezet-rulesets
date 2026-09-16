rule Webshell_cfm_shell_RID2E53 : DEMO SCRIPT T1505_003 WEBSHELL {
   meta:
      description = "Laudanum Injector Tools - file shell.cfm"
      author = "Florian Roth"
      reference = "http://laudanum.inguardians.com/"
      date = "2015-06-22 11:09:41"
      score = 75
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      
      tags = "DEMO, SCRIPT, T1505_003, WEBSHELL"
      minimum_yara = "3.5.0"
      
   strings:
      $s1 = "Executable: <Input type=\"text\" name=\"cmd\" value=\"cmd.exe\"><br>" fullword ascii
      $s2 = "<cfif ( #suppliedCode# neq secretCode )>" fullword ascii
      $s3 = "<cfif IsDefined(\"form.cmd\")>" fullword ascii
   condition: 
      filesize < 20KB and 2 of them
}