rule Derusbi_Kernel_Driver_WD_UDFS_RID31F5 : APT DEMO EXE FILE T1014 T1543_003 {
   meta:
      description = "Detects Derusbi Kernel Driver"
      author = "Florian Roth"
      reference = "http://blog.airbuscybersecurity.com/post/2015/11/Newcomers-in-the-Derusbi-family"
      date = "2015-12-15 13:44:41"
      score = 80
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      hash1 = "1b449121300b0188ff9f6a8c399fb818d0cf53fd36cf012e6908a2665a27f016"
      hash2 = "50174311e524b97ea5cb4f3ea571dd477d1f0eee06cd3ed73af39a15f3e6484a"
      hash3 = "6cdb65dbfb2c236b6d149fd9836cb484d0608ea082cf5bd88edde31ad11a0d58"
      tags = "APT, DEMO, EXE, FILE, T1014, T1543_003"
      minimum_yara = "3.5.0"
      
   strings:
      $x1 = "\\\\.\\pipe\\usbpcex%d" fullword wide
      $x2 = "\\\\.\\pipe\\usbpcg%d" fullword wide
      $x3 = "\\??\\pipe\\usbpcex%d" fullword wide
      $x4 = "\\??\\pipe\\usbpcg%d" fullword wide
      $x5 = "$$$--Hello" fullword ascii
      $x6 = "Wrod--$$$" fullword ascii
      $s1 = "\\Registry\\User\\%s\\Software\\Microsoft\\Windows\\CurrentVersion\\Internet Settings" wide
      $s2 = "Update.dll" fullword ascii
      $s3 = "\\Registry\\Machine\\SYSTEM\\CurrentControlSet\\Control\\WMI" wide
      $s4 = "\\Driver\\nsiproxy" wide
      $s5 = "HOST: %s" fullword ascii
   condition: 
      uint16 ( 0 ) == 0x5a4d and filesize < 800KB and ( 2 of ( $x* ) or all of ( $s* ) )
}