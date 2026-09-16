rule sig_238_cmd_2 {
   meta:
      description = "Disclosed hacktool set (old stuff) - file cmd.jsp"
      license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
      author = "Florian Roth (Nextron Systems)"
      date = "23.11.14"
      score = 60
      hash = "be4073188879dacc6665b6532b03db9f87cfc2bb"
      id = "5fae3c4a-aeeb-5e02-9071-3980a39a19a9"
   strings:
      $s0 = "Process child = Runtime.getRuntime().exec(" ascii
      $s1 = "InputStream in = child.getInputStream();" fullword ascii
      $s2 = "String cmd = request.getParameter(\"" ascii
      $s3 = "while ((c = in.read()) != -1) {" fullword ascii
      $s4 = "<%@ page import=\"java.io.*\" %>" fullword ascii
   condition:
      all of them
}