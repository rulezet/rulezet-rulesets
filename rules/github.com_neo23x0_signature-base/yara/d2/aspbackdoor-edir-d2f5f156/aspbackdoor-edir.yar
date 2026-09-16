rule aspbackdoor_EDIR {
   meta:
      description = "Disclosed hacktool set (old stuff) - file EDIR.ASP"
      license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
      author = "Florian Roth (Nextron Systems)"
      date = "23.11.14"
      score = 60
      hash = "03367ad891b1580cfc864e8a03850368cbf3e0bb"
      id = "0895091a-b620-5746-8245-d44716ec2bbe"
   strings:
      $s1 = "response.write \"<a href='index.asp'>" fullword ascii
      $s3 = "if Request.Cookies(\"password\")=\"" ascii
      $s6 = "whichdir=server.mappath(Request(\"path\"))" fullword ascii
      $s7 = "Set fs = CreateObject(\"Scripting.FileSystemObject\")" fullword ascii
      $s19 = "whichdir=Request(\"path\")" fullword ascii
   condition:
      all of them
}