rule Webshell_Insomnia_RID2DE4 : DEMO T1505_003 WEBSHELL {
   meta:
      description = "Insomnia Webshell - file InsomniaShell.aspx"
      author = "Florian Roth"
      reference = "http://www.darknet.org.uk/2014/12/insomniashell-asp-net-reverse-shell-bind-shell/"
      date = "2014-12-09 10:51:11"
      score = 80
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      
      tags = "DEMO, T1505_003, WEBSHELL"
      minimum_yara = "3.5.0"
      
   strings:
      $s0 = "Response.Write(\"- Failed to create named pipe:\");" fullword ascii
      $s1 = "Response.Output.Write(\"+ Sending {0}<br>\", command);" fullword ascii
      $s2 = "String command = \"exec master..xp_cmdshell 'dir > \\\\\\\\127.0.0.1" ascii
      $s3 = "Response.Write(\"- Error Getting User Info<br>\");" fullword ascii
      $s4 = "string lpCommandLine, ref SECURITY_ATTRIBUTES lpProcessAttributes," fullword ascii
      $s5 = "[DllImport(\"Advapi32.dll\", SetLastError = true)]" fullword ascii
      $s9 = "username = DumpAccountSid(tokUser.User.Sid);" fullword ascii
      $s14 = "//Response.Output.Write(\"Opened process PID: {0} : {1}<br>\", p" ascii
   condition: 
      3 of them
}