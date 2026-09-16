rule _20160921_17ed90b369ab37cb5f1e7dcf8f6bb253_20160921_1b3a88384cf7_3436 {
  meta:
    description = "datamaliciousorder - from files 20160921_17ed90b369ab37cb5f1e7dcf8f6bb253.js, 20160921_1b3a88384cf704def4ce92e01728a1df.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "81de0ae14e0c288b697a0e3c7f3ced9b68b8377e75dff5322d654841e642a8a7"
    hash2       = "dc931c610cc8536a2b67001c5b7c93e6dc26026d0daa00576bf3e92b3bd564a7"

  strings:
    $s1 = "MDb\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"RLk\";})(),(function f000(){return \"IPu\";})(),(funct" ascii
    $s2 = "){return \"YTp\";})(),(function f000(){return \"XTn\";})(),(function f000(){return \"DIa\";})(),(function f000(){return \"Zj\";}" ascii
    $s3 = ")(),(function f000(){return \"Kw\";})(),(function f000(){return \"Kw\";})(),(function f000(){return \"Qz\";})(),(function f000()" ascii
    $s4 = "Gn\";})(),(function f000(){return \"MBb\";})(),(function f000(){return \"IPu\";})(),(function f000(){return \"Lp\";})(),(functio" ascii
    $s5 = "nction f000(){return \"DYs\";})(),(function f000(){return \"YTp\";})(),(function f000(){return \"Yi\";})(),(function f000(){retu" ascii
    $s6 = "00(){return \"DYx\";})(),(function f000(){return \"TRc\";})(),(function f000(){return \"QDg\";})(),(function f000(){return \"Nv" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}