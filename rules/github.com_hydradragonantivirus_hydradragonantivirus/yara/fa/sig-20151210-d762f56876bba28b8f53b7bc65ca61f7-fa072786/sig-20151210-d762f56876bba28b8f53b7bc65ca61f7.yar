rule sig_20151210_d762f56876bba28b8f53b7bc65ca61f7 {
  meta:
    description = "datamaliciousorder - file 20151210_d762f56876bba28b8f53b7bc65ca61f7.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "5f9c59af98a739d4601641ef717b1916a35be64e66efb70c21bc90d96754c573"

  strings:
    $s1  = "function hlMDvDf(YsfErvWRYadLBrwYyvCmvZDHahBpIoWWSpVr) {return !isNaN(parseFloat(YsfErvWRYadLBrwYyvCmvZDHahBpIoWWSpVr)) && isFin" ascii
    $s2  = "function hlMDvDf(YsfErvWRYadLBrwYyvCmvZDHahBpIoWWSpVr) {return !isNaN(parseFloat(YsfErvWRYadLBrwYyvCmvZDHahBpIoWWSpVr)) && isFin" ascii
    $s3  = "BedrOpZ=(-462+462)/713;while(true){if(BedrOpZ>=(-25+281)/2){break;}YzNDQtvJOyplz[BedrOpZ]=String.fromCharCode(BedrOpZ);BedrOpZ++" ascii
    $s4  = "BedrOpZ=(-462+462)/713;while(true){if(BedrOpZ>=(-25+281)/2){break;}YzNDQtvJOyplz[BedrOpZ]=String.fromCharCode(BedrOpZ);BedrOpZ++" ascii
    $s5  = "function CpIDmmszpCffmIWaHAjyCHcEiWYhhMyXXtykVvLPBQMwIEiQjVAFdo(bVcYAZaZjhxZH,uRexsefYDoMKXt){ return YzNDQtvJOyplz[QScIC(bVcYAZ" ascii
    $s6  = "function otYFpvxubUlnfDmIL(rxMte){FzMsiWIGaXD= '';for(JktTEZrOofw=(-306+306)/937; JktTEZrOofw < (203+937)/570; JktTEZrOofw++) {p" ascii
    $s7  = "function QKFNTtYXWfC(AkQCfqUC,rAJDCy){return AkQCfqUC.split(rAJDCy)}" fullword ascii
    $s8  = "function CpIDmmszpCffmIWaHAjyCHcEiWYhhMyXXtykVvLPBQMwIEiQjVAFdo(bVcYAZaZjhxZH,uRexsefYDoMKXt){ return YzNDQtvJOyplz[QScIC(bVcYAZ" ascii
    $s9  = "} return FzMsiWIGaXD}" fullword ascii
    $s10 = "function QScIC(DqUiWyQGMNc,xvGRqgALzlOOL,cfCfRclZ){RFCd=parseInt(DqUiWyQGMNc,xvGRqgALzlOOL);PSzVi=RFCd.toString(cfCfRclZ);return" ascii
    $s11 = "function otYFpvxubUlnfDmIL(rxMte){FzMsiWIGaXD= '';for(JktTEZrOofw=(-306+306)/937; JktTEZrOofw < (203+937)/570; JktTEZrOofw++) {p" ascii
    $s12 = "function QScIC(DqUiWyQGMNc,xvGRqgALzlOOL,cfCfRclZ){RFCd=parseInt(DqUiWyQGMNc,xvGRqgALzlOOL);PSzVi=RFCd.toString(cfCfRclZ);return" ascii
    $s13 = " PSzVi;}function zmjaNSVgtIwxgzP(rfyMFjvPZKnChbmFF){eval(rfyMFjvPZKnChbmFF)}" fullword ascii
    $s14 = "cdGGWNpy[JktTEZrOofw]=(-200+200)/732; while(true) { if(pcdGGWNpy[JktTEZrOofw] > rxMte[JktTEZrOofw].length-(326+163)/489) { break" ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}