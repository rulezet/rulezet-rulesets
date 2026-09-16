rule sig_20170415_023174de2f005996573953c9d5f6f312 {
  meta:
    description = "datamaliciousorder - file 20170415_023174de2f005996573953c9d5f6f312.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "b84daa8dfae87925211564f62cca35200add2b827d9508221d68b613a1ee0e5f"

  strings:
    $x1  = "            e132[[\"run\"][0]]([lieu(0, \"From\", [\"cmd.exe /c \\\"po\"]) + a4cc(0, \"bin\", [\"wershell  $Chat='\"]) + Rico(0," ascii
    $x2  = "            e132[[\"run\"][0]]([lieu(0, \"From\", [\"cmd.exe /c \\\"po\"]) + a4cc(0, \"bin\", [\"wershell  $Chat='\"]) + Rico(0," ascii
    $s3  = " -S';$\"]) + _a(0, \"ie9\", [\"l\"]) + esc(0, \"was\", [\"e='^ex\"]) + Undo(0, \"md\", [\"t.exe'');(Ne';$\"]) + fw(0, \"Tags\", " ascii
    $s4  = "(0, \"U\", [\"^ $path';$Mona='^=('\"]) + are(0, \"TODO\", [\";$Pal\"]) + sw(0, \"RTL\", [\"i=\"]) + mid(0, \"lt\", [\"'^Set-Exec" ascii
    $s5  = "} /* authorities who in their eyes had no understanding for  */" fullword ascii
    $s6  = "xbf(0, \"acee\", [\"?f=3\"]) + May(0, \"dz\", [\".g';$ccc='^cope Proc\"]) + list(0, \"fail\", [\"ess; $path'; Invok\"]) + e087(0" ascii
    $s7  = "]) + gn(0, \"c84\", [\"df='^h); Start-Proc\"]) + Manx(0, \"e047\", [\"ess';\"]) + gbp(0, \"bell\", [\"$WXR='^ \"]) + who(0, \"da" ascii
    $s8  = "\"]) + str(0, \"xap\", [\"$Mona+$HEAD+\"]) + samp(0, \"usec\", [\"$le+$FTP+$\"]) + h3(0, \"bkg\", [\"ID3+$ll+$\"]) + Help(0, \"a" ascii
    $s9  = "} /* similar readiness for sacrifice, will never be found again;  */" fullword ascii
    $s10 = "} /* I restrained myself from appearing in public, though I  */" fullword ascii
    $s11 = "} /* difference as perhaps the success of a filibuster community is  */" fullword ascii
    $s12 = "// which posterity found later every reason to thank them on " fullword ascii
    $s13 = "function GET(docx, span, Hack) {" fullword ascii
    $s14 = "function f328(selW, fill, fake) {" fullword ascii
    $s15 = "} /* human cultural development, as its highest task.  */" fullword ascii
    $s16 = "// countries which were on the lookout, and alarm the phi- " fullword ascii
    $s17 = "} /* craftsmen die out gradually and thus the worker's possi-  */" fullword ascii
    $s18 = "} /* Not much has been done to date towards reaching this  */" fullword ascii
    $s19 = "} /* neglected cultural forces of a nationality. Out of the emer-  */" fullword ascii
    $s20 = "} /* the same year (1923) the new German chancellor, Gustav  */" fullword ascii

  condition:
    uint16(0) == 0x2a2f and
    1 of ($x*) and 4 of them
}