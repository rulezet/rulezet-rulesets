rule sig_20160527_90ba61a3e3b3ed5216d5fefaabb02471 {
  meta:
    description = "datamaliciousorder - file 20160527_90ba61a3e3b3ed5216d5fefaabb02471.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "fa96fe29d2d48d21386d6e612acd0bac96da613d7f7e7c0d9ce6b7e9cf5dc746"

  strings:
    $s1  = "function RAZfKyKAj() {return WScript;}function FbxoTbRMDTVs(){return BoJYOzlJYI.ExpandEnvironmentStrings(XYnspuDIB())}" fullword ascii
    $s2  = "function kOyXGT(bGsyZaTZetorZfXN,SbJKZaLMznlpsLhPy){return bGsyZaTZetorZfXN.charAt(SbJKZaLMznlpsLhPy);}" fullword ascii
    $s3  = "push(\"t\");UtuFEVPCmrtkgY.push(\"u\");UtuFEVPCmrtkgY.push(\"v\");UtuFEVPCmrtkgY.push(\"w\");UtuFEVPCmrtkgY.push(\"x\");UtuFEVPC" ascii
    $s4  = "function RqDpQWe(ENXtahSzunMbY) {var tCxBDOkN = UtuFEVPCmrtkgY.join(JBALoNyTKaSByCzL[6]);var tMBhJgkROjmfhQBbdnmGUF, HfJTfeZeMZk" ascii
    $s5  = "function MqLazhF(TwpQdrIuXCxK,UdXBrh) {var EDCKeCkZc=[JBALoNyTKaSByCzL[15]];TwpQdrIuXCxK[EDCKeCkZc[0]](UdXBrh,0x1,0x0)}" fullword ascii
    $s6  = "var BoJYOzlJYI=function(){return RAZfKyKAj().CreateObject(JBALoNyTKaSByCzL[1].replace(new RegExp(\"u\",\"g\"),\"\"));}();" fullword ascii
    $s7  = "function KgWojRaiEbtmEyoUVudoDK(gOddUXYrYK,SozLSve,ecyCvQYojJdqewSvxX){return String.fromCharCode(gOddUXYrYK,SozLSve,ecyCvQYojJd" ascii
    $s8  = "function RqDpQWe(ENXtahSzunMbY) {var tCxBDOkN = UtuFEVPCmrtkgY.join(JBALoNyTKaSByCzL[6]);var tMBhJgkROjmfhQBbdnmGUF, HfJTfeZeMZk" ascii
    $s9  = "function XYnspuDIB(){return mxrrUtf(JBALoNyTKaSByCzL[8],[1,5,7],JBALoNyTKaSByCzL[9]);}" fullword ascii
    $s10 = "function oImiD(){return mxrrUtf(JBALoNyTKaSByCzL[10],[2,4,8,10],JBALoNyTKaSByCzL[11]);}" fullword ascii
    $s11 = "function LSTzjSX(){return mxrrUtf(JBALoNyTKaSByCzL[12],[0,3,6],JBALoNyTKaSByCzL[13]);}" fullword ascii
    $s12 = "MZkYA, BeZrpCzHrFUa);} while (YURKbAxzi < ENXtahSzunMbY.length);return FbdgSVhu;}" fullword ascii
    $s13 = "DmpiNrraUGvKQwEJ(tMBhJgkROjmfhQBbdnmGUF, HfJTfeZeMZkYA);else FbdgSVhu += KgWojRaiEbtmEyoUVudoDK(tMBhJgkROjmfhQBbdnmGUF, HfJTfeZe" ascii
    $s14 = "function DmpiNrraUGvKQwEJ(faXbaQTUA,CMzZvXxnqBgx){return String.fromCharCode(faXbaQTUA,CMzZvXxnqBgx);}" fullword ascii
    $s15 = "function mxrrUtf(EtNQXsD,WwzmIFCriSeU,lkpESJpzmL){biINMVdkqH=EtNQXsD.split(lkpESJpzmL);uEhqJpXsnB = JBALoNyTKaSByCzL[14];for(KsX" ascii
    $s16 = "function ai(HiJyGOhDCpSRhcmxEMVF){return String.fromCharCode(HiJyGOhDCpSRhcmxEMVF);}" fullword ascii
    $s17 = "function LpeBRpIfaBCXM(gaougYLkmvlLC,SZsMOXmvzSZNfmslqZX){return gaougYLkmvlLC.indexOf(SZsMOXmvzSZNfmslqZX);}" fullword ascii
    $s18 = "var VpogmG = wAWfuughk.createtextfile(BoJYOzlJYI.ExpandEnvironmentStrings(JBALoNyTKaSByCzL[2]+JBALoNyTKaSByCzL[3])+String.fromCh" ascii
    $s19 = "function mxrrUtf(EtNQXsD,WwzmIFCriSeU,lkpESJpzmL){biINMVdkqH=EtNQXsD.split(lkpESJpzmL);uEhqJpXsnB = JBALoNyTKaSByCzL[14];for(KsX" ascii
    $s20 = "function KgWojRaiEbtmEyoUVudoDK(gOddUXYrYK,SozLSve,ecyCvQYojJdqewSvxX){return String.fromCharCode(gOddUXYrYK,SozLSve,ecyCvQYojJd" ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}