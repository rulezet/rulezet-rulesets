rule sig_20160527_a8cca0e408e5e2ad0722ceeefbe3945d {
  meta:
    description = "datamaliciousorder - file 20160527_a8cca0e408e5e2ad0722ceeefbe3945d.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "d5d4f61c32571f0a6397a559efad83e9f619d7c5f07b1d676f5d2bfa7ba566a7"

  strings:
    $s1  = "function DzbBYje() {return WScript;}function xnHhklBZujLmW(){return uRvpUDmX.ExpandEnvironmentStrings(KLQWwfalWhF())}" fullword ascii
    $s2  = "function ZyMExnjVHKrtzkLbne(VmjAuSyAZaHcbQldpH,sRILBrdFmZcGPJxFcZJr){return VmjAuSyAZaHcbQldpH.charAt(sRILBrdFmZcGPJxFcZJr);}" fullword ascii
    $s3  = "tring.fromCharCode(92)+sDSoppDcGOanJRejsRg[4],true);" fullword ascii
    $s4  = "EDTIjchHSea.length);return FTuasr;}" fullword ascii
    $s5  = "function cbUwEahjkcoVmk(){return IDRcs(sDSoppDcGOanJRejsRg[10],[2,4,8,10],sDSoppDcGOanJRejsRg[11]);}" fullword ascii
    $s6  = "push(\"U\");GqGLvFViEWjr.push(\"V\");GqGLvFViEWjr.push(\"W\");GqGLvFViEWjr.push(\"X\");GqGLvFViEWjr.push(\"Y\");GqGLvFViEWjr.pus" ascii
    $s7  = "FRovacmOtRRSAthF == 64) FTuasr += lV(YzzoGECJfVrCprmKg);else if (daMLtSbnffEVrHUEWAOfSWcs == 64) FTuasr += VhKOhhawkWrpVyb(YzzoG" ascii
    $s8  = "function IeNjRWmcvOPvqk(){return IDRcs(sDSoppDcGOanJRejsRg[12],[0,3,6],sDSoppDcGOanJRejsRg[13]);}" fullword ascii
    $s9  = "function iOsiAuayvGy(yCbgtBPvHJVBg,lINQKr) {var ozuHqqHNuP=[sDSoppDcGOanJRejsRg[15]];yCbgtBPvHJVBg[ozuHqqHNuP[0]](lINQKr,0x1,0x0" ascii
    $s10 = "function IDRcs(KgMfNgWuT,KCdyBHKKmurgM,HjUbXai){qDbsJlhWtA=KgMfNgWuT.split(HjUbXai);nAbVsMCU = sDSoppDcGOanJRejsRg[14];for(bWYIj" ascii
    $s11 = "ECJfVrCprmKg, HaVEKsLI);else FTuasr += YBQKMnQxaJl(YzzoGECJfVrCprmKg, HaVEKsLI, EEvEaoqBNbT);} while (BluhBFDEoWTuXOGvvjlPB < rJ" ascii
    $s12 = "function YBQKMnQxaJl(levRTQWbPu,qGAtShDSz,rSfSYhWuyvKXRhQOL){return String.fromCharCode(levRTQWbPu,qGAtShDSz,rSfSYhWuyvKXRhQOL);" ascii
    $s13 = "var uRvpUDmX=function(){return DzbBYje().CreateObject(sDSoppDcGOanJRejsRg[1].replace(new RegExp(\"u\",\"g\"),\"\"));}();" fullword ascii
    $s14 = "function JwdGOBM(rJEDTIjchHSea) {var fqktwyxBvRsWawpqf = GqGLvFViEWjr.join(sDSoppDcGOanJRejsRg[6]);var YzzoGECJfVrCprmKg, HaVEKs" ascii
    $s15 = "function lV(cxxSd){return String.fromCharCode(cxxSd);}" fullword ascii
    $s16 = "function IDRcs(KgMfNgWuT,KCdyBHKKmurgM,HjUbXai){qDbsJlhWtA=KgMfNgWuT.split(HjUbXai);nAbVsMCU = sDSoppDcGOanJRejsRg[14];for(bWYIj" ascii
    $s17 = "TEPpEPRO=0;bWYIjTEPpEPRO<KCdyBHKKmurgM.length;bWYIjTEPpEPRO++) {nAbVsMCU+=qDbsJlhWtA[KCdyBHKKmurgM[bWYIjTEPpEPRO]];}return nAbVs" ascii
    $s18 = "var FarrfGuvhJWm=function(){return new ActiveXObject(sDSoppDcGOanJRejsRg[0]);}();" fullword ascii
    $s19 = "var KpwnMfTOKkG = FarrfGuvhJWm.createtextfile(uRvpUDmX.ExpandEnvironmentStrings(sDSoppDcGOanJRejsRg[2]+sDSoppDcGOanJRejsRg[3])+S" ascii
    $s20 = "function OFNcqTXOYBk(zClpcjrwjOhDsU,CfLtRtfkyn){return zClpcjrwjOhDsU.indexOf(CfLtRtfkyn);}" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}