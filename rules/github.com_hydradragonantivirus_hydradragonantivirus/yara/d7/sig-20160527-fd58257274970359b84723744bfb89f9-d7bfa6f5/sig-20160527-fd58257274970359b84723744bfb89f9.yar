rule sig_20160527_fd58257274970359b84723744bfb89f9 {
  meta:
    description = "datamaliciousorder - file 20160527_fd58257274970359b84723744bfb89f9.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "1d0bb9b8892ede07c9b1245fc9203f0872721265feb62536c26ea475e29b9853"

  strings:
    $s1  = "function DijRYxTLhmsMMr() {return WScript;}function jlrLTsHb(){return EkrXzbR.ExpandEnvironmentStrings(YyHvvR())}" fullword ascii
    $s2  = "function XMYuThgSWiYzmCsZTCDfyle(qkkvtxAUyLYmsNOJUmYnQl,CCFUCJdS){return qkkvtxAUyLYmsNOJUmYnQl.charAt(CCFUCJdS);}" fullword ascii
    $s3  = "function TDTTtlqvr(PuoXgfvWmbWwD) {var ZwDfUZRUTgGWBSahcGOE = qDIDPFkaI.join(KJNQUHQLwbyGQLSL[6]);var mitQXRlShcPiTYMgH, WWySLUr" ascii
    $s4  = "function NhDZmwnWUO(){return pMKnvwa(KJNQUHQLwbyGQLSL[10],[2,4,8,10],KJNQUHQLwbyGQLSL[11]);}" fullword ascii
    $s5  = "function pMKnvwa(mNFRWTBKGjnzrF,lKlHKC,giSrVlKuwKJBo){SuGMjzrt=mNFRWTBKGjnzrF.split(giSrVlKuwKJBo);ldAkxeGGKp = KJNQUHQLwbyGQLSL" ascii
    $s6  = "function NIvzRJPLlqaPmearnye(MFjGWiGzWJNHSdvnCsU,ptyARlbDp,plYgxdQ){return String.fromCharCode(MFjGWiGzWJNHSdvnCsU,ptyARlbDp,plY" ascii
    $s7  = "(uoqoBjxdQijntBfjItEJv < PuoXgfvWmbWwD.length);return fpNygXSr;}" fullword ascii
    $s8  = "var QfkDTdZVvc=function(){return new ActiveXObject(KJNQUHQLwbyGQLSL[0]);}();" fullword ascii
    $s9  = "var uAekIXz = QfkDTdZVvc.createtextfile(EkrXzbR.ExpandEnvironmentStrings(KJNQUHQLwbyGQLSL[2]+KJNQUHQLwbyGQLSL[3])+String.fromCha" ascii
    $s10 = "function TDTTtlqvr(PuoXgfvWmbWwD) {var ZwDfUZRUTgGWBSahcGOE = qDIDPFkaI.join(KJNQUHQLwbyGQLSL[6]);var mitQXRlShcPiTYMgH, WWySLUr" ascii
    $s11 = "function pMKnvwa(mNFRWTBKGjnzrF,lKlHKC,giSrVlKuwKJBo){SuGMjzrt=mNFRWTBKGjnzrF.split(giSrVlKuwKJBo);ldAkxeGGKp = KJNQUHQLwbyGQLSL" ascii
    $s12 = "function RKRCZVXInUsIKx(KZUOXNPH,SrLyKsWEaxZcPAgSmVBxfPEG){return KZUOXNPH.indexOf(SrLyKsWEaxZcPAgSmVBxfPEG);}" fullword ascii
    $s13 = "function YyHvvR(){return pMKnvwa(KJNQUHQLwbyGQLSL[8],[1,5,7],KJNQUHQLwbyGQLSL[9]);}" fullword ascii
    $s14 = "function RlBHhMBYJK(hIZGipyEgQti,bEWzTSROTrsaTDRSzYtVj){return String.fromCharCode(hIZGipyEgQti,bEWzTSROTrsaTDRSzYtVj);}" fullword ascii
    $s15 = "rCode(92)+KJNQUHQLwbyGQLSL[4],true);" fullword ascii
    $s16 = "var EkrXzbR=function(){return DijRYxTLhmsMMr().CreateObject(KJNQUHQLwbyGQLSL[1].replace(new RegExp(\"u\",\"g\"),\"\"));}();" fullword ascii
    $s17 = "[14];for(TVGWAIKibja=0;TVGWAIKibja<lKlHKC.length;TVGWAIKibja++) {ldAkxeGGKp+=SuGMjzrt[lKlHKC[TVGWAIKibja]];}return ldAkxeGGKp.su" ascii
    $s18 = "function OF(KSsTWtMEwAvJZSJKJ){return String.fromCharCode(KSsTWtMEwAvJZSJKJ);}" fullword ascii
    $s19 = "(DnwDOVNPhgJdGCqyqeJwC == 64) fpNygXSr += OF(mitQXRlShcPiTYMgH);else if (aCkwqtcHLBzCeEbOAf == 64) fpNygXSr += RlBHhMBYJK(mitQXR" ascii
    $s20 = "function ZXOkeawobHgBW(){return pMKnvwa(KJNQUHQLwbyGQLSL[12],[0,3,6],KJNQUHQLwbyGQLSL[13]);}" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}