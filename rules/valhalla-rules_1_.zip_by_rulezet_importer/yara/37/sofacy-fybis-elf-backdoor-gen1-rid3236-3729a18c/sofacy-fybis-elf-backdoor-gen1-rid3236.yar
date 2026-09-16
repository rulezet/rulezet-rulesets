rule Sofacy_Fybis_ELF_Backdoor_Gen1_RID3236 : APT DEMO FILE G0007 G0019 LINUX RUSSIA {
   meta:
      description = "Detects Sofacy Fysbis Linux Backdoor_Naikon_APT_Sample1"
      author = "Florian Roth"
      reference = "http://researchcenter.paloaltonetworks.com/2016/02/a-look-into-fysbis-sofacys-linux-backdoor/"
      date = "2016-02-13 13:55:31"
      score = 80
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      modified = "2023-01-20"
      hash1 = "02c7cf55fd5c5809ce2dce56085ba43795f2480423a4256537bfdfda0df85592"
      hash2 = "8bca0031f3b691421cb15f9c6e71ce193355d2d8cf2b190438b6962761d0c6bb"
      tags = "APT, DEMO, FILE, G0007, G0019, LINUX, RUSSIA"
      minimum_yara = "3.5.0"
      
   strings:
      $x1 = "Your command not writed to pipe" fullword ascii
      $x2 = "Terminal don`t started for executing command" fullword ascii
      $x3 = "Command will have end with \\n" fullword ascii
      $s1 = "WantedBy=multi-user.target' >> /usr/lib/systemd/system/" ascii
      $s2 = "Success execute command or long for waiting executing your command" fullword ascii
      $s3 = "ls /etc | egrep -e\"fedora*|debian*|gentoo*|mandriva*|mandrake*|meego*|redhat*|lsb-*|sun-*|SUSE*|release\"" fullword ascii
      $s4 = "rm -f /usr/lib/systemd/system/" ascii
      $s5 = "ExecStart=" fullword ascii
      $s6 = "<table><caption><font size=4 color=red>TABLE EXECUTE FILES</font></caption>" fullword ascii
   condition: 
      ( uint16 ( 0 ) == 0x457f and filesize < 500KB and 1 of ( $x* ) ) or ( 1 of ( $x* ) and 3 of ( $s* ) )
}