rule Webshell_asp_file_RID2DE9 : DEMO FILE T1505_003 WEBSHELL {
   meta:
      description = "Laudanum Injector Tools - file file.asp"
      author = "Florian Roth"
      reference = "http://laudanum.inguardians.com/"
      date = "2015-06-22 10:52:01"
      score = 75
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      
      tags = "DEMO, FILE, T1505_003, WEBSHELL"
      minimum_yara = "3.5.0"
      
   strings:
      $s1 = "' *** Written by Tim Medin <tim@counterhack.com>" fullword ascii
      $s2 = "Response.BinaryWrite(stream.Read)" fullword ascii
      $s3 = "Response.Write(Response.Status & Request.ServerVariables(\"REMOTE_ADDR\"))" fullword ascii
      $s4 = "%><a href=\"<%=Request.ServerVariables(\"URL\")%>\">web root</a><br/><%" fullword ascii
      $s5 = "set folder = fso.GetFolder(path)" fullword ascii
      $s6 = "Set file = fso.GetFile(filepath)" fullword ascii
   condition: 
      uint16 ( 0 ) == 0x253c and filesize < 30KB and 5 of them
}