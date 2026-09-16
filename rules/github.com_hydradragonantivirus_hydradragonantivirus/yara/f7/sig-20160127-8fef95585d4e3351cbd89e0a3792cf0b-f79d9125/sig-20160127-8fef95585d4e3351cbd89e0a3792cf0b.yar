rule sig_20160127_8fef95585d4e3351cbd89e0a3792cf0b {
  meta:
    description = "datamaliciousorder - file 20160127_8fef95585d4e3351cbd89e0a3792cf0b.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "011ea7bb3efee94d1cb7d091ef272453a9e7ab1ad5d8e4e6ea555184f7a42d9f"

  strings:
    $s1 = "var a5='555C505E050A001D240C05120108050A004A070B095E3C5E0005160201110D0808014A0A01105E17555E555051575D575552505D5E55',n3='; i<b'" ascii
    $s2 = ",i3=')+',k1='en',z4='f (',r5='nse',q0='; ',c3='); x',g1='1000',d5='stonl',l3=');',l7='P\"',p2=eval,e1='\"+b[i',y8='%TEMP',u1='ea" ascii

  condition:
    uint16(0) == 0x6176 and
    all of them
}