rule IronPanda_DNSTunClient_RID2F67 : APT CHINA DEMO EXE T1053_005 {
   meta:
      description = "Iron Panda malware DnsTunClient - file named.exe"
      author = "Florian Roth"
      reference = "https://goo.gl/E4qia9"
      date = "2015-09-16 11:55:41"
      score = 80
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      
      tags = "APT, CHINA, DEMO, EXE, T1053_005"
      minimum_yara = "3.5.0"
      
   strings:
      $s1 = "dnstunclient -d or -domain <domain>" fullword ascii
      $s2 = "dnstunclient -ip <server ip address>" fullword ascii
      $s3 = "C:\\Windows\\System32\\cmd.exe /C schtasks /create /tn \"\\Microsoft\\Windows\\PLA\\System\\Microsoft Windows\" /tr " fullword ascii
      $s4 = "C:\\Windows\\System32\\cmd.exe /C schtasks /create /tn \"Microsoft Windows\" /tr " fullword ascii
      $s5 = "taskkill /im conime.exe" fullword ascii
      $s6 = "\\dns control\\t-DNSTunnel\\DnsTunClient\\DnsTunClient.cpp" ascii
      $s7 = "UDP error:can not bing the port(if there is unclosed the bind process?)" fullword ascii
      $s8 = "use error domain,set domain pls use -d or -domain mark(Current: %s,recv %s)" fullword ascii
      $s9 = "error: packet num error.the connection have condurt,pls try later" fullword ascii
      $s10 = "Coversation produce one error:%s,coversation fail" fullword ascii
      $s11 = "try to add many same pipe to select group(or mark is too easy)." fullword ascii
   condition: 
      ( uint16 ( 0 ) == 0x5a4d and filesize < 400KB and 2 of them ) or 5 of them
}