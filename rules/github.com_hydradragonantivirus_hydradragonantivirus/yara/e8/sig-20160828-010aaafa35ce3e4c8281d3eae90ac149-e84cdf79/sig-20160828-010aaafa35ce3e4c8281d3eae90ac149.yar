rule sig_20160828_010aaafa35ce3e4c8281d3eae90ac149 {
  meta:
    description = "datamaliciousorder - file 20160828_010aaafa35ce3e4c8281d3eae90ac149.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "783442bcb39deeccf53ba23140d70dd7d358f164bff18d5d983693f15c32d068"

  strings:
    $s1 = "RH) {return WScript[XUNYHJ(\"43C72R65F61T74G65T4FH62U6AH65V63I74V\")](LFODVRH)};function USPGJEK() {var DOYFCIVN=false;try {AQDP" ascii
    $s2 = "var DEVSQVDFO=\"p hVywvzmAJg JXJ3A9iX9 Ml8lzW B Rimu0315IZpqJu Km 0M 8KY2GpgAo l8cTIW6 E0dzU n gN 8u8h us DmOn\";function XUNYHJ" ascii
    $s3 = "var DEVSQVDFO=\"p hVywvzmAJg JXJ3A9iX9 Ml8lzW B Rimu0315IZpqJu Km 0M 8KY2GpgAo l8cTIW6 E0dzU n gN 8u8h us DmOn\";function XUNYHJ" ascii
    $s4 = "A72O\")]()==new Array(XUNYHJ(\"32N30V31N36Q\"))[0]) if ((!USPGJEK())) {var PXJLMX=XUNYHJ(\"57Q53E63S72G69I70Y74L2EZ53M68A65N6CB6" ascii
    $s5 = "TEN=\"\";for (var GBAMTC=577;GBAMTC<7332; GBAMTC++) {BSTEN+= XUNYHJ(\"66H6FV72J58W30J\"); };if (new Date()[XUNYHJ(\"67L65Y74M59Z" ascii
    $s6 = "DE31S\"),false);HMLMVJYE[XUNYHJ(\"53T65H74V52I65W71J75W65K73X74K48Y65L61Y64M65B72P\")](XUNYHJ(\"55R73F65T72G2DU41H67U65H6EV74I\"" ascii
    $s7 = "QUXA+WFPLB+COXFPVY+MPWOXA+YUPUG+DXNUARCF+XPALD+YJFRMU+KZJCA+QIRVPGFXO+DBFSHSADK](XAXLNH);};return OKXGZOS;};function FWGKG(LFODV" ascii
    $s8 = "\"c\";FEDHE=\"c\";QZMPWJE=\"d\"; DOYFCIVN=FWGKG(QZMPWJE+AQDPA+FEDHE); } catch (OSQLCPFD) { DOYFCIVN=false; }; return DOYFCIVN;};" ascii

  condition:
    uint16(0) == 0x6176 and
    all of them
}