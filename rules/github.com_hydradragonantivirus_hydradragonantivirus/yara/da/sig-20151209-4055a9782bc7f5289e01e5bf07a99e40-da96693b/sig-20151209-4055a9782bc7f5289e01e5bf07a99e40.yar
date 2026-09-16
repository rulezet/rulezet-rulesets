rule sig_20151209_4055a9782bc7f5289e01e5bf07a99e40 {
  meta:
    description = "datamaliciousorder - file 20151209_4055a9782bc7f5289e01e5bf07a99e40.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "362936164ec8347c93d664b91434e6378b7797c8c03b6600172a43c9f1be8428"

  strings:
    $s1  = "function jBPeqYi(nIOemUXdZCzCpmRtjKSzQQyoZTQVSyqyEyRp) {return !isNaN(parseFloat(nIOemUXdZCzCpmRtjKSzQQyoZTQVSyqyEyRp)) && isFin" ascii
    $s2  = "function jBPeqYi(nIOemUXdZCzCpmRtjKSzQQyoZTQVSyqyEyRp) {return !isNaN(parseFloat(nIOemUXdZCzCpmRtjKSzQQyoZTQVSyqyEyRp)) && isFin" ascii
    $s3  = "function cTEPv(cqCRkXhEvSt,EIAadYegOOrLk,JCzvaqnD){kmLs=parseInt(cqCRkXhEvSt,EIAadYegOOrLk);WaslC=kmLs.toString(JCzvaqnD);return" ascii
    $s4  = "function OhxJFKnOaEHOWBGdgFTNgocLnmwXBsMTmDGofwDgmPFzDqqCsvUqnf(BawcgIIGgVUFW,PSyvhsGwGAqBSb){ return KGnJz[cTEPv(BawcgIIGgVUFW[" ascii
    $s5  = "function fpzkbVJRgQM(MWJbgYdi,tugRGI){return MWJbgYdi.split(tugRGI)}" fullword ascii
    $s6  = " WaslC;}function tNtsXtQMIOiJelZ(ZHVEJTZaSXxeAfmwf){eval(ZHVEJTZaSXxeAfmwf)}" fullword ascii
    $s7  = ";}} return JxAjZFSfceo}" fullword ascii
    $s8  = "function cTEPv(cqCRkXhEvSt,EIAadYegOOrLk,JCzvaqnD){kmLs=parseInt(cqCRkXhEvSt,EIAadYegOOrLk);WaslC=kmLs.toString(JCzvaqnD);return" ascii
    $s9  = "function OhxJFKnOaEHOWBGdgFTNgocLnmwXBsMTmDGofwDgmPFzDqqCsvUqnf(BawcgIIGgVUFW,PSyvhsGwGAqBSb){ return KGnJz[cTEPv(BawcgIIGgVUFW[" ascii
    $s10 = "function nBmEQbfoonNtgnPNZ(PRgSc){JxAjZFSfceo= '';for(ggTZFemJkmB=(-300+300)/332; ggTZFemJkmB < (362+768)/565; ggTZFemJkmB++) {Q" ascii
    $s11 = "ZDWZUMyq[ggTZFemJkmB]=(-478+478)/149; while(true) { if(QZDWZUMyq[ggTZFemJkmB] > PRgSc[ggTZFemJkmB].length-(223+53)/276) { break;" ascii
    $s12 = "function nBmEQbfoonNtgnPNZ(PRgSc){JxAjZFSfceo= '';for(ggTZFemJkmB=(-300+300)/332; ggTZFemJkmB < (362+768)/565; ggTZFemJkmB++) {Q" ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}