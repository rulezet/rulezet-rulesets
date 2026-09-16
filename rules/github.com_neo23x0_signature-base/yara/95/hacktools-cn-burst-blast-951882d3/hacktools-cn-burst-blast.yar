rule Hacktools_CN_Burst_Blast {
   meta:
      description = "Disclosed hacktool set - file Blast.bat"
      license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
      author = "Florian Roth (Nextron Systems)"
      date = "17.11.14"
      score = 60
      hash = "b07702a381fa2eaee40b96ae2443918209674051"
      id = "9ac723c4-e88d-5fb3-b18f-c8b764c8acf3"
   strings:
      $s0 = "@sql.exe -f ip.txt -m syn -t 3306 -c 5000 -u http:" ascii
      $s1 = "@echo off" fullword ascii
   condition:
      all of them
}