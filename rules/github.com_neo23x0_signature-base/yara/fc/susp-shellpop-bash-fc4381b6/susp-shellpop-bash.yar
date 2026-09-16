rule SUSP_shellpop_Bash {
   meta:
      description = "Detects susupicious bash command"
      author = "Tobias Michalski"
      reference = "https://github.com/0x00-0x00/ShellPop"
      date = "2018-05-18"
      modified = "2025-04-11"
      score = 70
      hash1 = "36fad575a8bc459d0c2e3ad626e97d5cf4f5f8bedc56b3cc27dd2f7d88ed889b"
      id = "771b7d01-272a-5986-af07-7417b84c52ed"
   strings:
      $x1 = "bash -i >& /dev/tcp/" ascii
      $x2 = "bash -i >& /dev/tcp/" ascii base64

      $fp1 = "bash -i >& /dev/tcp/IP/PORT" ascii
   condition:
      1 of ($x*) and not 1 of ($fp*)
}