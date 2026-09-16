rule Gsecdump_password_dump_file {
   meta:
      description = "Detects a gsecdump output file"
      license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
      author = "Florian Roth (Nextron Systems)"
      reference = "https://t.co/OLIj1yVJ4m"
      date = "2018-03-06"
      score = 65
      id = "c7c8ab61-f728-5eb2-a5e3-b3dd84980870"
   strings:
      $x1 = "Administrator(current):500:" ascii
   condition:
      uint32be(0) == 0x41646d69 and filesize < 3000 and $x1 at 0
}