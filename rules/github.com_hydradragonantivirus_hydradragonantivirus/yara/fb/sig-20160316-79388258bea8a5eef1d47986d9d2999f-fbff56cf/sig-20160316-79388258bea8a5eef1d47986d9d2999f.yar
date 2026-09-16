rule sig_20160316_79388258bea8a5eef1d47986d9d2999f {
  meta:
    description = "datamaliciousorder - file 20160316_79388258bea8a5eef1d47986d9d2999f.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "e7491871724a3f9c44ab4522a24680b6c02bce190abba2cf3a0c3573c256645e"

  strings:
    $s1 = "while (ZAUsXJSF[YVWdOweeUM + EPgPZuLAKVjJNk + RECwtSUxio + xRsnFzzcX + NAhDLLdHnBfaro] < 4 ) {WScript[kjoIxHzyjfAJKl + ZsfEmjDgg" ascii
    $s2 = "while (ZAUsXJSF[YVWdOweeUM + EPgPZuLAKVjJNk + RECwtSUxio + xRsnFzzcX + NAhDLLdHnBfaro] < 4 ) {WScript[kjoIxHzyjfAJKl + ZsfEmjDgg" ascii
    $s3 = "XnvrMj + khDvziuQEl + owVLRlnjLXXegR + HFllMeCMW + iwizntFWye + jwL, false);" fullword ascii
    $s4 = "function eMoVVsMDj(n){return dUYEMVnxAuni + UlkWKbNCmgUuFDp + WKKGKZpcE + XnQOcKadWE + mJrUAI + NyWUEFjCon + swpZzCPpPW + qSImVS" ascii
    $s5 = "function eMoVVsMDj(n){return dUYEMVnxAuni + UlkWKbNCmgUuFDp + WKKGKZpcE + XnQOcKadWE + mJrUAI + NyWUEFjCon + swpZzCPpPW + qSImVS" ascii
    $s6 = "ZAUsXJSF[wUNqcMNFtR + olAfPhJdltExum](zXquOBfitQBOy + rPyijtXYSpmM, LWUHuLLlEB + XkVlyYoVqAYFOAl + BiJNysVPIPPDu + AjUjJYK + AhK" ascii
    $s7 = "function PTfhEfnzQwqm(dpBdW){CDDlh[siOYYizyPkdLF + medOkKUPvOEsd](dpBdW, 0, 0);}" fullword ascii
    $s8 = "var mrXczgCy = new Date();" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    all of them
}