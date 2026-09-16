rule sig_20160531_3429176c67dab8ef79e59c27026185a3 {
  meta:
    description = "datamaliciousorder - file 20160531_3429176c67dab8ef79e59c27026185a3.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "1354bb46a8e396c2417c2874fcf3b02eb6edfdc68210421ef939315a6a16b855"

  strings:
    $s1  = "var ijRQQN=function(){return WScript.CreateObject(SBJoadkpVmegVAInfmg[2].replace(new RegExp(\"u\",\"g\"),\"\"));}();" fullword ascii
    $s2  = "function KZadlEeGElzdMjO(viUGeqtLMOANVQ,RsJzIAWqzV){return viUGeqtLMOANVQ.charAt(RsJzIAWqzV);}" fullword ascii
    $s3  = "(isSFDSRtVMif,0x1,0x0)}function nRlgMPp(VNiMpxnJdqV,HDhwkToBKbGWRt,FAuDZw){var upfuKI=VNiMpxnJdqV.createtextfile(HDhwkToBKbGWRt," ascii
    $s4  = "true);upfuKI.WriteLine(FAuDZw);upfuKI.Close();}" fullword ascii
    $s5  = "function YWHfJlPpRgqOC(){return ijRQQN.ExpandEnvironmentStrings(CRghJOKAB())}" fullword ascii
    $s6  = "(isSFDSRtVMif,0x1,0x0)}function nRlgMPp(VNiMpxnJdqV,HDhwkToBKbGWRt,FAuDZw){var upfuKI=VNiMpxnJdqV.createtextfile(HDhwkToBKbGWRt," ascii
    $s7  = "TBRyUtpgGLrcSkdVAO += ZUAMgMdkvPobodiTc(ZiSHRpiPk, OkWiBygN, EvDbZyvHVi);} while (PQgEeLDeJXRaTtMedHKUV < rIGqyglxdcUjf.length);" ascii
    $s8  = "function tefnlnQe(YdwCqOyOdJRNEWEnHXDGvnb,KKqwNpCQNcpWvGQUKDCTQjnv){return YdwCqOyOdJRNEWEnHXDGvnb.indexOf(KKqwNpCQNcpWvGQUKDCTQ" ascii
    $s9  = "return ftTBRyUtpgGLrcSkdVAO;}" fullword ascii
    $s10 = "tTBRyUtpgGLrcSkdVAO += YL(ZiSHRpiPk);else if (UuzoaeJBoR == 64) ftTBRyUtpgGLrcSkdVAO += vuqHPtpkeCg(ZiSHRpiPk, OkWiBygN);else ft" ascii
    $s11 = "function jeiqWjUXUCN(){return ySgwGvgT(SBJoadkpVmegVAInfmg[13],[0,3,6],SBJoadkpVmegVAInfmg[14]);}" fullword ascii
    $s12 = "function ZUAMgMdkvPobodiTc(QkkIiwxHB,rIidKgXTpiUaOSKfzySvlqo,cSqMkrYRfVtHZUFPOuf){return String.fromCharCode(QkkIiwxHB,rIidKgXTp" ascii
    $s13 = "function ZUAMgMdkvPobodiTc(QkkIiwxHB,rIidKgXTpiUaOSKfzySvlqo,cSqMkrYRfVtHZUFPOuf){return String.fromCharCode(QkkIiwxHB,rIidKgXTp" ascii
    $s14 = "var woeOiQJU=function(){return new ActiveXObject(SBJoadkpVmegVAInfmg[1]);}();" fullword ascii
    $s15 = "function vuqHPtpkeCg(FAfgoL,ZJaHoB){return String.fromCharCode(FAfgoL,ZJaHoB);}" fullword ascii
    $s16 = "function ySgwGvgT(JUFuWhD,LWvFMmyzprekXi,ByDVhgzhLjd){NopGIB=JUFuWhD.split(ByDVhgzhLjd);hoBlFXsBh = SBJoadkpVmegVAInfmg[0];for(O" ascii
    $s17 = "function ySgwGvgT(JUFuWhD,LWvFMmyzprekXi,ByDVhgzhLjd){NopGIB=JUFuWhD.split(ByDVhgzhLjd);hoBlFXsBh = SBJoadkpVmegVAInfmg[0];for(O" ascii
    $s18 = "function CRghJOKAB(){return ySgwGvgT(SBJoadkpVmegVAInfmg[9],[1,5,7],SBJoadkpVmegVAInfmg[10]);}" fullword ascii
    $s19 = "function ZaFzjScxip(){return ySgwGvgT(SBJoadkpVmegVAInfmg[11],[2,4,8,10],SBJoadkpVmegVAInfmg[12]);}" fullword ascii
    $s20 = "function YL(lEsRsunoOrhxrYAEQcmrUko){return String.fromCharCode(lEsRsunoOrhxrYAEQcmrUko);}" fullword ascii

  condition:
    uint16(0) == 0x7566 and
    8 of them
}