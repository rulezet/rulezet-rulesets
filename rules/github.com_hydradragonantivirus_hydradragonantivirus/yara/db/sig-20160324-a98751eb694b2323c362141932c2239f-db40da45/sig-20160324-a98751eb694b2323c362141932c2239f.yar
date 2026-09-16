rule sig_20160324_a98751eb694b2323c362141932c2239f {
  meta:
    description = "datamaliciousorder - file 20160324_a98751eb694b2323c362141932c2239f.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "b474e1174acf718e3426385c560a4033c938dd18fa5389c6780790f68f6ccc4d"

  strings:
    $x1 = "var o80='co',b86='\"+',w58='WScri',j11='2);',u8=')+cs',y78='aup',i66='one',c71='wo *',y95='wmf *',h2='q+f',c7='t ',b91='+\"7',j9" ascii
    $s2 = "f15=' *.v',y18='It`',s90='xe\",2',e70=' you',f43='.from',m56='.\");',s50='*.ts',h79=' (dn',x83='.clos',g70='EM',z46='\"Wind',i97" ascii
    $s3 = ",a62='psd',t65='in (*',f37='+\".',e52='rit',a71='; xa.',b15='=\"',v5=' desk',c26=') ',s11='}; }',k37='cou',t40='rypto',i12='RYP'" ascii

  condition:
    uint16(0) == 0x6176 and
    1 of ($x*) and all of them
}