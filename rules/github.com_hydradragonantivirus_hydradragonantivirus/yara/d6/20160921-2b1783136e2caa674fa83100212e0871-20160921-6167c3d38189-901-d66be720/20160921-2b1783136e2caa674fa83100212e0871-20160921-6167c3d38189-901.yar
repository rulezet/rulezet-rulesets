rule _20160921_2b1783136e2caa674fa83100212e0871_20160921_6167c3d38189_901 {
  meta:
    description = "datamaliciousorder - from files 20160921_2b1783136e2caa674fa83100212e0871.js, 20160921_6167c3d38189e7b1134d16083ffbd574.js, 20160921_fd5fc067457571e92a95bd16158d41e6.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "4f4f696f319827ea3bc8e0b927eddbd7a588f390148cae3276f1573d816d8889"
    hash2       = "02d7a73acd6af9940f585a0e89095467489ba0ac094eb93050d43dab5745e5bd"
    hash3       = "e32ed831874bb280ae970e019573b598cf97788865b3fea13118546e435353f9"

  strings:
    $s1  = "00(){return \"Km\";})(),(function f000(){return \"KXg\";})(),(function f000(){return \"MDb\";})(),(function f000(){return \"HJm" ascii
    $s2  = "){return \"Yi\";})(),(function f000(){return \"MDb\";})(),(function f000(){return \"DAp\";})(),(function f000(){return \"Iq\";})" ascii
    $s3  = "unction f000(){return \"MDb\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"Oh\";})(),(function f000(){ret" ascii
    $s4  = " \"HJm\";})(),(function f000(){return \"MBb\";})(),(function f000(){return \"Yz\";})(),(function f000(){return \"MDb\";})(),(fun" ascii
    $s5  = "(function f000(){return \"NBs\";})(),(function f000(){return \"OMd\";})(),(function f000(){return \"GGn\";})(),(function f000(){" ascii
    $s6  = "eturn \"Mt\";})(),(function f000(){return \"MDb\";})(),(function f000(){return \"Sj\";})(),(function f000(){return \"SGs\";})()," ascii
    $s7  = "Mj\";})(),(function f000(){return \"MDb\";})(),(function f000(){return \"Yv\";})(),(function f000(){return \"BQb\";})(),(functio" ascii
    $s8  = "(),(function f000(){return \"KXg\";})(),(function f000(){return \"OMd\";})(),(function f000(){return \"GGn\";})(),(function f000" ascii
    $s9  = "),(function f000(){return \"ZFe\";})(),(function f000(){return \"HJm\";})(),(function f000(){return \"MJq\";})(),(function f000(" ascii
    $s10 = "000(){return \"GGn\";})(),(function f000(){return \"DYs\";})(),(function f000(){return \"BQb\";})(),(function f000(){return \"TR" ascii
    $s11 = "(),(function f000(){return \"Wb\";})(),(function f000(){return \"Kw\";})(),(function f000(){return \"MDb\";})(),(function f000()" ascii
    $s12 = "function f000(){return \"YTp\";})(),(function f000(){return \"MDb\";})(),(function f000(){return \"Um\";})(),(function f000(){re" ascii
    $s13 = ";})(),(function f000(){return \"MDb\";})(),(function f000(){return \"Yv\";})(),(function f000(){return \"MMz\";})(),(function f0" ascii
    $s14 = "000(){return \"SGs\";})(),(function f000(){return \"MDb\";})(),(function f000(){return \"Tb\";})(),(function f000(){return \"KDh" ascii
    $s15 = "(function f000(){return \"SEo\";})(),(function f000(){return \"UEg\";})(),(function f000(){return \"KXg\";})(),(function f000(){" ascii
    $s16 = "tion f000(){return \"BMj\";})(),(function f000(){return \"MDb\";})(),(function f000(){return \"SEo\";})(),(function f000(){retur" ascii
    $s17 = "nction f000(){return \"MKa\";})(),(function f000(){return \"Ot\";})(),(function f000(){return \"Ot\";})(),(function f000(){retur" ascii
    $s18 = " f000(){return \"MMz\";})(),(function f000(){return \"Lo\";})(),(function f000(){return \"TKl\";})(),(function f000(){return \"M" ascii
    $s19 = "tion f000(){return \"Kw\";})(),(function f000(){return \"MDb\";})(),(function f000(){return \"KDh\";})(),(function f000(){return" ascii
    $s20 = "00(){return \"Yv\";})(),(function f000(){return \"IAa\";})(),(function f000(){return \"Mt\";})(),(function f000(){return \"GGn\"" ascii

  condition:
    (uint16(0) == 0x2f0a and (8 of them)
    ) or (all of them)
}