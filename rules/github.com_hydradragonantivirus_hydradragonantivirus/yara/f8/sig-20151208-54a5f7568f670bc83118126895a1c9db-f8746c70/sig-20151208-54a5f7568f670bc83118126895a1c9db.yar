rule sig_20151208_54a5f7568f670bc83118126895a1c9db {
  meta:
    description = "datamaliciousorder - file 20151208_54a5f7568f670bc83118126895a1c9db.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "2346b622a37bed77d089917171d3c5379778edd18fee5485be258737d86787c1"

  strings:
    $s1  = "function QcKYYvY(VszLtbjqvRjVGNRHbvkYbUOgYBPCnkSBuzeO) {return !isNaN(parseFloat(VszLtbjqvRjVGNRHbvkYbUOgYBPCnkSBuzeO)) && isFin" ascii
    $s2  = "push(\"112\");T.push(\"111\");T.push(\"110\");T.push(\"115\");T.push(\"101\");T.push(\"66\");T.push(\"111\");T.push(\"100\");T.p" ascii
    $s3  = "function QcKYYvY(VszLtbjqvRjVGNRHbvkYbUOgYBPCnkSBuzeO) {return !isNaN(parseFloat(VszLtbjqvRjVGNRHbvkYbUOgYBPCnkSBuzeO)) && isFin" ascii
    $s4  = "push(\"32\");T.push(\"13\");T.push(\"10\");T.push(\"32\");T.push(\"32\");T.push(\"32\");T.push(\"32\");T.push(\"118\");T.push(\"" ascii
    $s5  = "++;}} return dkLhdaQTYFX}" fullword ascii
    $s6  = "push(\"32\");T.push(\"13\");T.push(\"10\");T.push(\"32\");T.push(\"32\");T.push(\"32\");T.push(\"32\");T.push(\"125\");T.push(\"" ascii
    $s7  = "function HLraNDmubgNaqtdPc(HQwXf){dkLhdaQTYFX= '';for(ebIDbAQKzfM=(-317+317)/959; ebIDbAQKzfM < (580+354)/467; ebIDbAQKzfM++) {f" ascii
    $s8  = "push(\"13\");R.push(\"10\");R.push(\"118\");R.push(\"97\");R.push(\"114\");R.push(\"32\");R.push(\"83\");R.push(\"103\");R.push(" ascii
    $s9  = "push(\"114\");R.push(\"105\");R.push(\"112\");R.push(\"116\");R.push(\"46\");R.push(\"67\");R.push(\"114\");R.push(\"101\");R.pu" ascii
    $s10 = "push(\"79\");R.push(\"68\");R.push(\"34\");R.push(\"59\");R.push(\"13\");R.push(\"10\");R.push(\"118\");R.push(\"97\");R.push(\"" ascii
    $s11 = "push(\"45\");R.push(\"105\");R.push(\"110\");R.push(\"99\");R.push(\"108\");R.push(\"117\");R.push(\"100\");R.push(\"101\");R.pu" ascii
    $s12 = "function HLraNDmubgNaqtdPc(HQwXf){dkLhdaQTYFX= '';for(ebIDbAQKzfM=(-317+317)/959; ebIDbAQKzfM < (580+354)/467; ebIDbAQKzfM++) {f" ascii
    $s13 = "push(\"83\");T.push(\"121\");T.push(\"53\");T.push(\"56\");T.push(\"53\");T.push(\"50\");T.push(\"50\");T.push(\"121\");T.push(" ascii
    $s14 = "push(\"61\");T.push(\"32\");T.push(\"56\");T.push(\"48\");T.push(\"53\");T.push(\"48\");T.push(\"57\");T.push(\"48\");T.push(\"5" ascii
    $s15 = "RpHkxkjt[ebIDbAQKzfM]=(-550+550)/737; while(true) { if(fRpHkxkjt[ebIDbAQKzfM] > HQwXf[ebIDbAQKzfM].length-(-169+372)/203) { brea" ascii
    $s16 = "function YIQfRtxCkWbnKxXvzVbUCItwWVToWAUYaIcmVzXBWCstheUnFnfsrJ(anTLdbzNuLTot,vqGKeanYJfSfrY){ return HiAkLKrAxkuOx[NXNSc(anTLdb" ascii
    $s17 = "push(\"40\");T.push(\"57\");T.push(\"51\");T.push(\"51\");T.push(\"57\");T.push(\"52\");T.push(\"54\");T.push(\"44\");T.push(\"3" ascii
    $s18 = "push(\"32\");T.push(\"106\");T.push(\"79\");T.push(\"32\");T.push(\"61\");T.push(\"32\");T.push(\"49\");T.push(\"59\");T.push(\"" ascii
    $s19 = "function YIQfRtxCkWbnKxXvzVbUCItwWVToWAUYaIcmVzXBWCstheUnFnfsrJ(anTLdbzNuLTot,vqGKeanYJfSfrY){ return HiAkLKrAxkuOx[NXNSc(anTLdb" ascii
    $s20 = "function aFPKkrgxTPh(DqCMFQoG,OUxHIk){return DqCMFQoG.split(OUxHIk)}" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}