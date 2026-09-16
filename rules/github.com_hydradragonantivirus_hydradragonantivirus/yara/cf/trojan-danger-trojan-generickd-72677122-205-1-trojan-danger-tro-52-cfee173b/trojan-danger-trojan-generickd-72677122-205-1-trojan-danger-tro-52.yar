import "pe"
rule _Trojan_Danger_Trojan_GenericKD_72677122_205_1_Trojan_Danger_Tro_52 {
  meta:
    description = "datamaliciousorder - from files Trojan.Danger_Trojan.GenericKD.72677122_205_1.vir, Trojan.Danger_Trojan.GenericKD.72677122_207_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "7bc0e2e95d349dec3a8833a431f4aae9dbff6764155df3364a2ee38bc58406d7"
    hash2       = "c1f51ef65b4385b87a48b996c0efb7a5572e9b2f6b4382434a409ed0d388bbe4"

  strings:
    $s1  = "lgyq*x2003, or Professional Users 2003 - External) during a 12 month period. This includes order lines originating as external" fullword ascii
    $s2  = "519204320hpdoadu*x*x*x#$#$16w519204322goakydo*x*x*x#$#$16n519204323swpnknq*x*x*x#$#$16w519204324lejtgmh*x*x*x#$#$16j519204325wes" ascii
    $s3  = "ar Hosting Term may only be used for providing internet hosting services." fullword ascii
    $s4  = "Microsoft Software License Terms link or going to04343kxgkkrd*x*x*x#$#$16f519204344rrjmugf*x*x*x#$#$16c51920434specifying a 1 Ye" ascii
    $s5  = "the entire agreement, including any linked terms, because all of the terms are important and together4554sfgovvs*x*x*x#$#$16n519" ascii
    $s6  = "with your employees and agents that protect the confidentiality and proprietary rights of the confidential information of third*" ascii
    $s7  = "with your employees and agents that protect the confidentiality and proprietary rights of the confidential information of third*" ascii
    $s8  = "m*x*x*x#$#$16x51920460udmdmmve*x*x*x#$#$16e51920461koqhinad*x*x*x#$#$16f51920462bdggjura*x*x*x#$#You may acquire under a separat" ascii
    $s9  = "the entire agreement, including any linked terms, because all of the terms are important and together4554sfgovvs*x*x*x#$#$16n519" ascii
    $s10 = "activation. If you have not entered a product key during " fullword ascii
    $s11 = "THE DISPUTE WILL BE CONDUCTED EXCLUSIVELY BY BINDINGxD" fullword ascii
    $s12 = "services ordered and Oracle may end this agreement. Provisions that survive termination or expiration include those relating tox" ascii
    $s13 = "services ordered and Oracle may end this agreement. Provisions that survive termination or expiration include those relating tox" ascii
    $s14 = "e order the Premium Online Library or an individual Online Course for a term of 6 months" fullword ascii
    $s15 = "pfsb*x*x*x#$#$21a5199243ibwdypi*x*x*intellectual property rights, the Provider will indemnify the Recipient against the claim if" ascii
    $s16 = " Privacy Statement linked at the end of this agreement for more information." fullword ascii
    $s17 = "x*x*x#$#$16w519204322goakydo*x*x*x#$#$16n519204323swpnknq*x*x*x#$#$16w519204324lejtgmh*x*x*x#$#$16j519204325weslgyq*xOffice 2013" ascii
    $s18 = " the Recipient does the following:" fullword ascii
    $s19 = "Microsoft Software License Terms link or going to04343kxgkkrd*x*x*x#$#$16f519204344rrjmugf*x*x*x#$#$16c51920434specifying a 1 Ye" ascii
    $s20 = "be a CANEX Authorized Patron, you must be a*x*x*x#$#$16r519204441lohipis*x*x*x#$#$16a519204442xvwjsng*x*x*x#$#$16m519204444uqlns" ascii

  condition:
    (uint16(0) == 0x5a4d and pe.imphash() == "ed8f1702dd6496858461bf2bd4d53aa4" and (8 of them)
    ) or (all of them)
}