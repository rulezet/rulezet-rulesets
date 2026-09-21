import "pe"
rule sig_24952_0370_icedid_dll {
   meta:
      description = "24952-files - file 0370-1.dll"
      author = "The DFIR Report"
      reference = "https://thedfirreport.com/2024/06/10/icedid-brings-screenconnect-and-csharp-streamer-to-alphv-ransomware-deployment"
      date = "2024-05-27"
      hash1 = "fab34d1f0f906f64f95b9f244ae1fe090427e606a9c808c720e18e93a08ed84d"
   strings:
      $s1 = "Uafwqzthwt.dll" fullword wide
      $s2 = "vmqpdhqepbzvgd.dll" fullword ascii
      $s3 = "<?xml version=\"1.0\" encoding=\"UTF-8\" standalone=\"yes\"?><AFX_RIBBON><HEADER><VERSION>1</VERSION></HEADER><RIBBON_BAR><ELEME" ascii
      $s4 = "ETTE_TOP><ALWAYS_LARGE>FALSE</ALWAYS_LARGE><INDEX_SMALL>-1</INDEX_SMALL><INDEX_LARGE>-1</INDEX_LARGE><DEFAULT_COMMAND>TRUE</DEFA" ascii
      $s5 = "<?xml version=\"1.0\" encoding=\"UTF-8\" standalone=\"yes\"?><AFX_RIBBON><HEADER><VERSION>1</VERSION></HEADER><RIBBON_BAR><ELEME" ascii
      $s6 = "GE><INDEX_SMALL>-1</INDEX_SMALL><INDEX_LARGE>-1</INDEX_LARGE><DEFAULT_COMMAND>TRUE</DEFAULT_COMMAND><BUTTON_MODE>TRUE</BUTTON_MO" ascii
      $s7 = "RGE>-1</INDEX_LARGE><DEFAULT_COMMAND>TRUE</DEFAULT_COMMAND><ELEMENTS><ELEMENT><ELEMENT_NAME>Button_Gallery</ELEMENT_NAME><ID><NA" ascii
      $s8 = "E>RibbonBar</ELEMENT_NAME><ENABLE_TOOLTIPS>TRUE</ENABLE_TOOLTIPS><ENABLE_TOOLTIPS_DESCRIPTION>TRUE</ENABLE_TOOLTIPS_DESCRIPTION>" ascii
      $s9 = "?Dllmain@@YAXPEAUHWND__@@PEAUHINSTANCE__@@PEADH@Z" fullword ascii
      $s10 = "operator<=>" fullword ascii
      $s11 = "operator co_await" fullword ascii
      $s12 = "TODO: layout dialog bar" fullword wide
      $s13 = "jqmlstixr" fullword ascii
      $s14 = "gvedbud" fullword ascii
      $s15 = "gmxfbhpcfswjou" fullword ascii
      $s16 = "dprxcfouvkzjrlhh" fullword ascii
      $s17 = "fzwtwxbpu" fullword ascii
      $s18 = "blgvptinnadhkyxm" fullword ascii
      $s19 = "woqlkigmjywhni" fullword ascii
      $s20 = "xijpfpsthuek" fullword ascii
   condition:
      uint16(0) == 0x5a4d and filesize < 1000KB and
      ( pe.imphash() == "e7125b885fcd1eea77d2881eaaa53c4d" and ( pe.exports("EntryFunct") and pe.exports("aefwtcvfayc") and pe.exports("akoglmgw") and pe.exports("avlvewny") and pe.exports("bhirvxqpmj") and pe.exports("blgvptinnadhkyxm") ) or 8 of them )
}