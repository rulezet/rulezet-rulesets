rule sig_20151222_aadfd97b46ec67a055ee7e7c450e7e7e {
  meta:
    description = "datamaliciousorder - file 20151222_aadfd97b46ec67a055ee7e7c450e7e7e.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "e0e07b449e98bc23cfd54e95dbb78389807bdd4becd76aa74baa4c052af026d2"

  strings:
    $s1 = "var str=\"5553515E0508010724011C1405101001070C4A070B095E3C5E1414050A00054A0B1C0210144A070B095E17565E555051545C5557545D515E55\";v" ascii
    $s2 = "',h3='for ',t0='1000',z9='\"theb',x5='= 20',p7='ope',a3='P%',z5='t(\"',b1='1;',d7='rin',o2='\"+b',d0=' ws =',z4='AD',p4=' =',l9=" ascii

  condition:
    uint16(0) == 0x6176 and
    all of them
}