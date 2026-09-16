rule W32ChirB_pe_infector {
   meta:
      description = "pp.exe - Chir.B"
      author = "wit0k"
      reference = ""
      date = "2018-08-31"
      hash1 = "d2f46265c39c21bc544b9ab4fad708bae7f33defff32f280806d48e3eb31e510"
   strings:
      $s1 = "<html><HEAD></HEAD><body bgColor=3D#ffffff><iframe src=3Dcid:THE-CID height=3D0 width=3D0></iframe></body></html>" fullword ascii
      $s2 = "<html><script language=\"JavaScript\">window.open(\"readme.eml\", null,\"resizable=no,top=6000,left=6000\")</script></html>" fullword ascii
      $s3 = /FROM: .{1,20}@yahoo\.com/ fullword ascii nocase
      $s4 = /Content-Type: audio\/x-wav; name=.{1,20}.exe/ fullword ascii nocase
      $s5 = "\\runouce.exe" fullword ascii
      $s6 = "Net Send * My god! Some one killed ChineseHacker-2 Monitor" fullword ascii
      $s7 = /readme\.eml/ fullword ascii
      $s8 = "Runonce" fullword ascii
      $s9 = "SUBJECT: %s is comming!" fullword ascii
      $s10 = /MAIL FROM: .{1,20}@btamail\.net.\cn/ fullword ascii
      $s11 = "Content-id: THE-CID" fullword ascii
      $s12 = "btamail.net.cn" fullword ascii
      $ds1 = "This program cannot be run in DOS mode"
   condition:
      (uint16(0) == 0x5a4d or uint16(0) == 0x4d5a ) and ( 8 of them ) and (filesize < 120KB) and not $ds1
}