rule iam_iam_RID29DE : APT DEMO EXE FILE {
   meta:
      description = "Semiautomatically generated YARA rule - file iam.exe"
      author = "Florian Roth"
      reference = "http://www.coresecurity.com/corelabs-research/open-source-tools/pass-hash-toolkit"
      date = "2015-07-10 01:55:01"
      score = 80
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      
      tags = "APT, DEMO, EXE, FILE"
      minimum_yara = "3.5.0"
      
   strings:
      $s1 = "<cmd>. Create a new logon session and run a command with the specified credentials (e.g.: -r cmd.exe)" fullword ascii
      $s2 = "iam.exe -h administrator:mydomain:" ascii
      $s3 = "An error was encountered when trying to change the current logon credentials!." fullword ascii
      $s4 = "optional parameter. If iam.exe crashes or doesn't work when run in your system, use this parameter." fullword ascii
      $s5 = "IAM.EXE will try to locate some memory locations instead of using hard-coded values." fullword ascii
      $s6 = "Error in cmdline!. Bye!." fullword ascii
      $s7 = "Checking LSASRV.DLL...." fullword ascii
   condition: 
      uint16 ( 0 ) == 0x5a4d and filesize < 300KB and all of them
}