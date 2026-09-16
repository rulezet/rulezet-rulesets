rule sig_20170118_197838f7e8c96c91ac764b554e2d9d06 {
  meta:
    description = "datamaliciousorder - file 20170118_197838f7e8c96c91ac764b554e2d9d06.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "636a1ce9ce646e790539f147027215adbfe2cdca07527d2299ea7ad16d36285a"

  strings:
    $s1  = "function String.prototype.s(){var EO3eJ36OPp=(((453<<32)<<(~-33))%(1>>32));var w5XpUkndu=this.split(\"\");if (Number(yNdAIA8NXcF" ascii
    $s2  = "while(KOacgXm==(((117178368<<0x2)>>(~-21))%(0x775f566dec4e8000/8601688843416928256))){HerCG6['' + ('d6', '1TX', 'oOeL'.s()) + ('" ascii
    $s3  = "while(HerCG6['' + ('ZJ5', 'Q_', 'Rf', 'rL'.s()) + ('Raw1', 'IZ', 'A03Z', '_SMQ', 'exXw'.s()) + ('Hz', 'AxU', '2uCFq', 'arapz'.s(" ascii
    $s4  = "while(HerCG6['' + ('ZJ5', 'Q_', 'Rf', 'rL'.s()) + ('Raw1', 'IZ', 'A03Z', '_SMQ', 'exXw'.s()) + ('Hz', 'AxU', '2uCFq', 'arapz'.s(" ascii
    $s5  = "while(KOacgXm==(((117178368<<0x2)>>(~-21))%(0x775f566dec4e8000/8601688843416928256))){HerCG6['' + ('d6', '1TX', 'oOeL'.s()) + ('" ascii
    $s6  = "6OPp=w5XpUkndu.length;return w5XpUkndu[w5XpUkndu.length-EO3eJ36OPp];}" fullword ascii
    $s7  = "var ZPFvdmMIJmTz=(((~-6876)<<(12<<32))>>(0x3*2));NCHLdtG=NCHLdtG+new Date();while(ZPFvdmMIJmTz>(((~-451)<<(0x800>>>0x6))%(0x1>>>" ascii
    $s8  = "var ZPFvdmMIJmTz=(((~-6876)<<(12<<32))>>(0x3*2));NCHLdtG=NCHLdtG+new Date();while(ZPFvdmMIJmTz>(((~-451)<<(0x800>>>0x6))%(0x1>>>" ascii
    $s9  = "function String.prototype.s(){var EO3eJ36OPp=(((453<<32)<<(~-33))%(1>>32));var w5XpUkndu=this.split(\"\");if (Number(yNdAIA8NXcF" ascii
    $s10 = "}catch(RpV5iUWgHbrh){};" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    all of them
}