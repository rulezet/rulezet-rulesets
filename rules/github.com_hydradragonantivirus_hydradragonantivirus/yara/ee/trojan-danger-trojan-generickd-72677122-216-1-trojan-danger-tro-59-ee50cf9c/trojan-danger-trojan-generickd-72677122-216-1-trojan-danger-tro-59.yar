import "pe"
rule _Trojan_Danger_Trojan_GenericKD_72677122_216_1_Trojan_Danger_Tro_59 {
  meta:
    description = "datamaliciousorder - from files Trojan.Danger_Trojan.GenericKD.72677122_216_1.vir, Trojan.Danger_Trojan.GenericKD.72677122_218_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "e519b2f25f4d4508cce62f0773a0793067b0386cfb7c3a358b6e0a826e640e2c"
    hash2       = "4bb64d4b281d9f4a390372a7f2c1ee0cc9be6ca984f65876d815cf8eddc82ef6"

  strings:
    $s1  = "agree to terminate that subset of licenses. The technical support fees for the remaining licenses will be priced in accordance45" ascii
    $s2  = " is defined as an individual authorized by you to access the hosted service, regardless of whether the individual" fullword ascii
    $s3  = "x*x*x#$#$16w519204322goakydo*x*x*x#$#$16n519204323swpnknq*x*x*x#$#$16w519204324lejtgmh*x*x*x#$#$16j519204325weslgyq*xMembership:" ascii
    $s4  = "materially reduce the level of services provided for supported programs" fullword ascii
    $s5  = "court (Section B.3) or in arbitration (Section B.4). The one-year period begins when the claim or disputethrough other computers" ascii
    $s6  = "IRE_OLSA_V120103_Def_V122304 Page 7 of 11 55uiatvdn*x*x*x#$#$16h519204356tfokdxn*x*x*x#$#$16n519204357modwrck*x*x*x#$#$16h519204" ascii
    $s7  = "Enterprise Edition) and the licensed program are running are counted for the purpose of" fullword ascii
    $s8  = "YOU PAID ORACLE FOR THE DEFICIENT PROGRAM OR SERVICES UNDER THIS AGREEMENT AS4537kihackh*x*x*x#$#$16d519204538gbjsqol*x*x*x#$#$1" ascii
    $s9  = "court (Section B.3) or in arbitration (Section B.4). The one-year period begins when the claim or disputethrough other computers" ascii
    $s10 = "YOU PAID ORACLE FOR THE DEFICIENT PROGRAM OR SERVICES UNDER THIS AGREEMENT AS4537kihackh*x*x*x#$#$16d519204538gbjsqol*x*x*x#$#$1" ascii
    $s11 = "IRE_OLSA_V120103_Def_V122304 Page 7 of 11 55uiatvdn*x*x*x#$#$16h519204356tfokdxn*x*x*x#$#$16n519204357modwrck*x*x*x#$#$16h519204" ascii
    $s12 = " or devices connected to the server over an internal or external network. The" fullword ascii
    $s13 = "*x*x#$#$16h51920444vijmprjh*x*x*x#$#$16y51920445dcmlmauu*x*x*x#$#$16u51920446leosqkpt*x*x*x#$#$1Server (Standard Edition and/or " ascii
    $s14 = "agree to terminate that subset of licenses. The technical support fees for the remaining licenses will be priced in accordance45" ascii
    $s15 = "ARBITRA TION CLA USE A ND CLASS ACTION WA IVER. IF YOU LIVE IN THE UNITED STATES,16g519204350futdtkw*x*x*x#$#$16f519204353dntowl" ascii
    $s16 = "ARBITRA TION CLA USE A ND CLASS ACTION WA IVER. IF YOU LIVE IN THE UNITED STATES,16g519204350futdtkw*x*x*x#$#$16f519204353dntowl" ascii

  condition:
    (uint16(0) == 0x5a4d and pe.imphash() == "5f5a65c93dba50abae85d14b9c0162e6" and (8 of them)
    ) or (all of them)
}