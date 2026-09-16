rule sig_20161206_5f443468c8f291a3b65621a9b0290daf {
  meta:
    description = "datamaliciousorder - file 20161206_5f443468c8f291a3b65621a9b0290daf.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "f35623c956daaf982528b1a9f6ebda441cfe28e725e5747927070fcde26c620f"

  strings:
    $s1  = "var zqabasl = \"bypass -\";" fullword ascii
    $s2  = "azbim.run(uzqignip + ikuwjy + gapkofky + bjaxokza + nvody + qovy + zqabasl + jvemij + uwevoqp + mvagow + felre + osviqa + uppuvk" ascii
    $s3  = "peril = 16.495 + peril;" fullword ascii
    $s4  = "ynwu + gsuhcu + ijex + opamc + yhunilt + unavoz + laxexdi + side + yxasorm + ykwavabb + hyhho + oxgorj + diledi + anbijza + lvin" ascii
    $s5  = "var skazla = undefined;" fullword ascii
    $s6  = "switch (sucexi()) {" fullword ascii
    $s7  = "var side = \"eva='^l'\";" fullword ascii
    $s8  = "var ovvyvekpoj = null;" fullword ascii
    $s9  = "if (lcyqzattugy === false) {" fullword ascii
    $s10 = "var qesovvy = null;" fullword ascii
    $s11 = "var ulsarvuxha = null;" fullword ascii
    $s12 = "var yrgawma = null;" fullword ascii
    $s13 = "if (eknoliluc === false) {" fullword ascii
    $s14 = "return xduxbev;" fullword ascii
    $s15 = "return ovvyvekpoj;" fullword ascii
    $s16 = "var ehfypzastu = typeof window;" fullword ascii
    $s17 = "function obsug() {" fullword ascii
    $s18 = "switch (okefysqo()) {" fullword ascii
    $s19 = "function sucexi() {" fullword ascii
    $s20 = "function xtytguhule() {" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}