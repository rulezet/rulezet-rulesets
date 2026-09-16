rule sig_20160531_65430c7a7b163f93f0d9a3f8bc2b35e8 {
  meta:
    description = "datamaliciousorder - file 20160531_65430c7a7b163f93f0d9a3f8bc2b35e8.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "7d14fe2d94981eb80fba92f454a4c367b8bac96268f7ce27f0567fc78866b687"

  strings:
    $s1  = "var XrlucU=function(){return WScript.CreateObject(SzPXufWnVNrZLomXkSw[2].replace(new RegExp(\"u\",\"g\"),\"\"));}();" fullword ascii
    $s2  = "function ClqeILfSDncvnezzD(nKnFKDRYspGpflyrfa,DASDQJGlQLZEHkLGlJtx){return nKnFKDRYspGpflyrfa.charAt(DASDQJGlQLZEHkLGlJtx);}" fullword ascii
    $s3  = "function yvlFLrgmDWQgj(){return XrlucU.ExpandEnvironmentStrings(scuwjiCfV())}" fullword ascii
    $s4  = "function HSgZTtPxAxayks(){return WTDAOCDCbhk(SzPXufWnVNrZLomXkSw[11],[2,4,8,10],SzPXufWnVNrZLomXkSw[12]);}" fullword ascii
    $s5  = "function crPbcldKBwD(KuSvVJdVQhxaF) {var lleJdgwapILbLjHLG = QGWRzHtCczVS.join(SzPXufWnVNrZLomXkSw[7]);var rRVMPGqTWUot, VpyRjxV" ascii
    $s6  = "function dbHjPQXly(){return WTDAOCDCbhk(SzPXufWnVNrZLomXkSw[13],[0,3,6],SzPXufWnVNrZLomXkSw[14]);}" fullword ascii
    $s7  = "var ZrdeU=function(){return new ActiveXObject(SzPXufWnVNrZLomXkSw[1]);}();" fullword ascii
    $s8  = "qTWUot, VpyRjxVCna);else NHzVDPIv += pPRPJCcosudagClBkElngF(rRVMPGqTWUot, VpyRjxVCna, PzwFqgQLwqFek);} while (VoxFOMKkqYWTUOqldn" ascii
    $s9  = "p < KuSvVJdVQhxaF.length);return NHzVDPIv;}" fullword ascii
    $s10 = "function PXaPvCBnk(UuWiMGDO,QyVGLZ) {var fcrrmqy=[SzPXufWnVNrZLomXkSw[15]];UuWiMGDO[fcrrmqy[0]]" fullword ascii
    $s11 = "function tJGeadOUzcFdzHoTJx(aSEKkRfxbBCiCT,AsaugpEUmSGqFSSeQwqN){return aSEKkRfxbBCiCT.indexOf(AsaugpEUmSGqFSSeQwqN);}" fullword ascii
    $s12 = "function WTDAOCDCbhk(PdCmGeuE,MWYCHeDMfkq,SDYOrSmBYrYGy){dzlKvDeFL=PdCmGeuE.split(SDYOrSmBYrYGy);WMNoMhD = SzPXufWnVNrZLomXkSw[0" ascii
    $s13 = "function Nc(hHNbTXFZbVXrbMSh){return String.fromCharCode(hHNbTXFZbVXrbMSh);}" fullword ascii
    $s14 = "];for(dHokAYTA=0;dHokAYTA<MWYCHeDMfkq.length;dHokAYTA++) {WMNoMhD+=dzlKvDeFL[MWYCHeDMfkq[dHokAYTA]];}return WMNoMhD.substring(3," ascii
    $s15 = "function scuwjiCfV(){return WTDAOCDCbhk(SzPXufWnVNrZLomXkSw[9],[1,5,7],SzPXufWnVNrZLomXkSw[10]);}" fullword ascii
    $s16 = "(QyVGLZ,0x1,0x0)}function hnNXYUJWVmlP(EiOUEPau,sixUwCkzy,qpVQUFg){var RyHcUAbTsGRg=EiOUEPau.createtextfile(sixUwCkzy,true);RyHc" ascii
    $s17 = "push(\"U\");QGWRzHtCczVS.push(\"V\");QGWRzHtCczVS.push(\"W\");QGWRzHtCczVS.push(\"X\");QGWRzHtCczVS.push(\"Y\");QGWRzHtCczVS.pus" ascii
    $s18 = "function crPbcldKBwD(KuSvVJdVQhxaF) {var lleJdgwapILbLjHLG = QGWRzHtCczVS.join(SzPXufWnVNrZLomXkSw[7]);var rRVMPGqTWUot, VpyRjxV" ascii
    $s19 = "function WTDAOCDCbhk(PdCmGeuE,MWYCHeDMfkq,SDYOrSmBYrYGy){dzlKvDeFL=PdCmGeuE.split(SDYOrSmBYrYGy);WMNoMhD = SzPXufWnVNrZLomXkSw[0" ascii
    $s20 = "(QyVGLZ,0x1,0x0)}function hnNXYUJWVmlP(EiOUEPau,sixUwCkzy,qpVQUFg){var RyHcUAbTsGRg=EiOUEPau.createtextfile(sixUwCkzy,true);RyHc" ascii

  condition:
    uint16(0) == 0x7566 and
    8 of them
}