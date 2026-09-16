rule infected_05_29_18_case109_case109_smevk {
  meta:
    description = "case109 - file smevk.php"
    author      = "Brian Laskowski"
    reference   = "https://github.com/Hestat/lw-yara"
    date        = "2018-05-29"
    hash1       = "c7645ec5826178f7848014085d950efc4cb3b8b3841d155be15102eadaca1475"

  strings:
    $s1  = "SmEvK_PaThAn Shell v3 Coded by Kashif Khan ." fullword ascii
    $s2  = "$deface_url = 'http://pastebin.com/raw.php?i=FHfxsFGT';  //deface url here(pastebin)." fullword ascii
    $s3  = "https://www.facebook.com/smevkpathan" fullword ascii
    $s4  = "smevkpathan@gmail.com" fullword ascii
    $s5  = "Edit Shell according to your choice." fullword ascii
    $s6  = "Domain read bypass." fullword ascii
    $s7  = "$auth_pass = \"rao1\";                                  //Your Password." fullword ascii
    $s8  = "//Change Shell Theme here//" fullword ascii
    $s9  = "ZhbHVlKTtyZXR1cm4gZmFsc2U7XCc+PGlucHV0IHR5cGU9dGV4dCBuYW1lPXBhcmFtPjxpbnB1dCB0eXBlPXN1Ym1pdCB2YWx1ZT0iPj4iPjwvZm9ybT48YnI+PHNwYW" ascii
    $s10 = "c+PGlucHV0IHR5cGU9dGV4dCBuYW1lPXBhcmFtPjxpbnB1dCB0eXBlPXN1Ym1pdCB2YWx1ZT0iPj4iPjwvZm9ybT48YnI+PHNwYW4+R2xvYiAobGlzdCBkaXIpPC9zcG" ascii
    $s11 = "xudWxsLCI2Iix0aGlzLnBhcmFtLnZhbHVlKTtyZXR1cm4gZmFsc2U7XCc+PGlucHV0IHR5cGU9dGV4dCBuYW1lPXBhcmFtPjxpbnB1dCB0eXBlPXN1Ym1pdCB2YWx1ZT" ascii
    $s12 = "#-------------------------------------------------------------------------------" fullword ascii
    $s13 = "onJykuIj4gc2VuZCB1c2luZyBBSkFYPGJyPjx0ZXh0YXJlYSBuYW1lPSdpbnB1dCcgc3R5bGU9J21hcmdpbi10b3A6NXB4JyBjbGFzcz1iaWdhcmVhPiIuaHRtbHNwZW" ascii
    $s14 = "NvcnMtNHUuY29tL2N1cnNvci8yMDEyLzAyLzExL2Nocm9tZS1wb2ludGVyLmh0bWwiIHRhcmdldD0iX2JsYW5rIiB0aXRsZT0iQ2hyb21lIFBvaW50ZXIiPjxpbWcgc3" ascii
    $s15 = "AuYmlnYXJlYSAgICB7IHdpZHRoOjEwMCU7aGVpZ2h0OjI1MHB4O21hcmdpbi10b3A6MHB4OyBib3JkZXItcmFkaXVzOjEwcHg7IGJvcmRlci1jb2xvcjonLiRUaGVtZS" ascii
    $s16 = "d3LmN1cnNvcnMtNHUuY29tL2N1cnNvci8yMDEyLzAyLzExL2Nocm9tZS1wb2ludGVyLmh0bWwiIHRhcmdldD0iX2JsYW5rIiB0aXRsZT0iQ2hyb21lIFBvaW50ZXIiPj" ascii
    $s17 = "dsemRHVnVJSEJ2Y25SY2JpSTdEUXAzYUdsc1pTZ3hLU0I3RFFvSllXTmpaWEIwS0VOUFRrNHNVeWs3RFFvSmFXWW9JU2drY0dsa1BXWnZjbXNwS1NCN0RRb0pDV1JwWl" ascii
    $s18 = "$UserName = \"rao1\";                                      //Your UserName here." fullword ascii
    $s19 = "$smevk = \"PD9waHAKCiRkZWZhdWx0X2FjdGlvbiA9ICdGaWxlc01hbic7CkBkZWZpbmUoJ1NFTEZfUEFUSCcsIF9fRklMRV9fKTsKaWYoIHN0cnBvcygkX1NFUlZFU" ascii
    $s20 = "$Theme = '#09B5A6';                                    //Change border-color accoriding to your choice." fullword ascii

  condition:
    (uint16(0) == 0x3f3c and
      filesize < 300KB and
      (8 of them)
    ) or (all of them)
}