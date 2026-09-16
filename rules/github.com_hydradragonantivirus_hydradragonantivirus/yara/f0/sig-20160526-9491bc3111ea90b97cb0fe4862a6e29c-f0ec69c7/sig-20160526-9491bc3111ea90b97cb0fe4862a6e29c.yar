rule sig_20160526_9491bc3111ea90b97cb0fe4862a6e29c {
  meta:
    description = "datamaliciousorder - file 20160526_9491bc3111ea90b97cb0fe4862a6e29c.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "c9d808f73707ae198f5b3e20c3d3eb63bc3995d185f403e5db7dfb91c9f26ce4"

  strings:
    $s1  = "os(323), 2) - 1))-266) & 0xff;bTYYttWqCTvaCj = xPdstVgJcLvFmMVJw>> (257 + Math.round((Math.pow(Math.sin(310), 2) + Math.pow(Math" ascii
    $s2  = ".cos(310), 2) - 1))-249) & 0xff;fQygBpEnpRYZOk = xPdstVgJcLvFmMVJw & 0xff;if (GPWEamchFuUWJXPmawnYdD == (727 + Math.round((Math." ascii
    $s3  = "pow(Math.sin(74), 2) + Math.pow(Math.cos(74), 2) - 1))-663)) FwJJArLsuYrqzGinG += h(gwehwTSYNGPURcWe);else if (NMAVWfmiEnJBksVwh" ascii
    $s4  = "function CFuhLRbWt(wQKVLEFoldBUz) {var LDZTTZYhkb = QvWnqJwk.join(dOoCSHawffjoPSjhNaaH[0]);var gwehwTSYNGPURcWe, bTYYttWqCTvaCj," ascii
    $s5  = "function FUsbefsIkczQtzb(UngFab,FJYaCDmK){return UngFab.charAt(FJYaCDmK);}" fullword ascii
    $s6  = "function h(HJhXSIcxpkeQiwRfSVDCTumt){return String.fromCharCode(HJhXSIcxpkeQiwRfSVDCTumt);}" fullword ascii
    $s7  = "function jAMXiUBLgZUNYbUfo(pLSnqxtcOpIQbkuStUPtFfow,atyecSrjFENFTJxKKdaTu){return String.fromCharCode(pLSnqxtcOpIQbkuStUPtFfow,a" ascii
    $s8  = "function ZbDzFCSmNmVcwtFWvY(qerihQyBNuzujHrLI,nJYHBkvt,DcKdqIcQQxiwikEs){return String.fromCharCode(qerihQyBNuzujHrLI,nJYHBkvt,D" ascii
    $s9  = "function CFuhLRbWt(wQKVLEFoldBUz) {var LDZTTZYhkb = QvWnqJwk.join(dOoCSHawffjoPSjhNaaH[0]);var gwehwTSYNGPURcWe, bTYYttWqCTvaCj," ascii
    $s10 = "o(gwehwTSYNGPURcWe, bTYYttWqCTvaCj);else FwJJArLsuYrqzGinG += ZbDzFCSmNmVcwtFWvY(gwehwTSYNGPURcWe, bTYYttWqCTvaCj, fQygBpEnpRYZO" ascii
    $s11 = "function GgbEfmxeyUHImiuytM(WjfnQWpLQpwXBALyk,jUwXrgjYmFvfYbmXagZTS){return WjfnQWpLQpwXBALyk.indexOf(jUwXrgjYmFvfYbmXagZTS);}" fullword ascii
    $s12 = "function ZbDzFCSmNmVcwtFWvY(qerihQyBNuzujHrLI,nJYHBkvt,DcKdqIcQQxiwikEs){return String.fromCharCode(qerihQyBNuzujHrLI,nJYHBkvt,D" ascii
    $s13 = "k);} while (RKgyrQSbUXdzwUOcHkpFS < wQKVLEFoldBUz.length);return FwJJArLsuYrqzGinG;}" fullword ascii
    $s14 = "function jAMXiUBLgZUNYbUfo(pLSnqxtcOpIQbkuStUPtFfow,atyecSrjFENFTJxKKdaTu){return String.fromCharCode(pLSnqxtcOpIQbkuStUPtFfow,a" ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}