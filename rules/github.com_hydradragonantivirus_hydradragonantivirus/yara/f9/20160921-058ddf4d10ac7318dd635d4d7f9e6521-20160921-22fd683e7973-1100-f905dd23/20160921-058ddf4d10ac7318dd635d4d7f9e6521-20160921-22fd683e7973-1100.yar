rule _20160921_058ddf4d10ac7318dd635d4d7f9e6521_20160921_22fd683e7973_1100 {
  meta:
    description = "datamaliciousorder - from files 20160921_058ddf4d10ac7318dd635d4d7f9e6521.js, 20160921_22fd683e7973fc938e9d6980e5e81789.js, 20160921_3065f95fdd47a96a00f0692965111ae8.js, 20160921_40f63eff81c24c0b6e27053222902225.js, 20160921_56407ccd21c5f8f4947d4df222e60442.js, 20160921_5645898a54dfcbd78b32ee6da656f545.js, 20160921_72beed3cbd321b62d224a35a01639682.js, 20160921_940fdd83fcdf499d0ebc071f779bd880.js, 20160921_aa7387335b72c30a3b2a33711bac8907.js, 20160921_e2617d9e437c12b61ada4700f8e426b8.js, 20160921_ee6d5c7dc2c03b89ea5ef53aa0c676a1.js, 20160921_f1bb498dcbb1f3aecbc35886be394f58.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "beed60d53c1dc194e146ec112b43046bd7ea366584d59483d351cd57e1208385"
    hash2       = "c3583ada9b0a35137add948ee4bd3182a5f977a0dbcc3a39c01ee288f703d566"
    hash3       = "78116ceaf58fe5711732c6fa5c646094dd87471f2d3ce65adbd7b478d5bbc1bb"
    hash4       = "6b71d253d7ac7dfb797132caac458cf74b81e67304218edbb764243d89e51bb1"
    hash5       = "bec8a0189f43e097fc0815a0bb39f2df50e4c37c7185ad70b3be3b0d17b8dd32"
    hash6       = "0d8d12c1edd9af4fca97f4e7013b538499acfb96d7d0bed0a7b5419e888829b1"
    hash7       = "ce3c3a93d2e5df0f850da4d79a5f697eaff66f1043058d62f80adad98b476839"
    hash8       = "b73c87ed73bc62067299b13aaa227535cbedafa1a7f74ad02273d1aad3a3449f"
    hash9       = "96ff6fd5b079de518bd1ded811f4e98bcf45211a849900012beeb7e498b7b721"
    hash10      = "732b58fdcabccece6ef3ce710e7c0ba505cd66ea292afad6fac2c48739151b46"
    hash11      = "ddd3db3929119812b70ad9f62bd3187b6108d24999c41a8ff5390bc9a60387a3"
    hash12      = "486454370a5dac6af41bfda9ac339e37120334ce5f7c4319bd0f8e9df9514b44"

  strings:
    $s1  = "u\";})(),(function fuck(){return \"GWo\";})(),(function fuck(){return \"UXf\";})(),(function fuck(){return \"Vb\";})(),(function" ascii
    $s2  = "n fuck(){return \"Vf\";})(),(function fuck(){return \"Zy\";})(),(function fuck(){return \"Dc\";})(),(function fuck(){return \"PD" ascii
    $s3  = "n \"Xw\";})(),(function fuck(){return \"DWe\";})(),(function fuck(){return \"Dc\";})(),(function fuck(){return \"YAv\";})(),(fun" ascii
    $s4  = "),(function fuck(){return \"Xw\";})(),(function fuck(){return \"Av\";})(),(function fuck(){return \"SUi\";})(),(function fuck(){" ascii
    $s5  = "),(function fuck(){return \"Xg\";})(),(function fuck(){return \"Sx\";})(),(function fuck(){return \"XCr\";})(),(function fuck(){" ascii
    $s6  = "n fuck(){return \"IOs\";})(),(function fuck(){return \"PDf\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return " ascii
    $s7  = "tion fuck(){return \"DWe\";})(),(function fuck(){return \"Dc\";})(),(function fuck(){return \"Xw\";})(),(function fuck(){return " ascii
    $s8  = "on fuck(){return \"Xw\";})(),(function fuck(){return \"YAv\";})(),(function fuck(){return \"Xg\";})(),(function fuck(){return \"" ascii
    $s9  = "eturn \"IPu\";})(),(function fuck(){return \"MIl\";})(),(function fuck(){return \"YQt\";})(),(function fuck(){return \"Ik\";})()" ascii
    $s10 = "eturn \"DWe\";})(),(function fuck(){return \"Dc\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"MBg\";})()" ascii
    $s11 = "(function fuck(){return \"DWe\";})(),(function fuck(){return \"Ot\";})(),(function fuck(){return \"Ar\";})(),(function fuck(){re" ascii
    $s12 = ";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"XCr\";})(),(function fuck(){return \"Wo\";})(),(function fu" ascii
    $s13 = "k(){return \"ZWu\";})(),(function fuck(){return \"Na\";})(),(function fuck(){return \"Xw\";})(),(function fuck(){return \"IPu\";" ascii
    $s14 = "rn \"Fv\";})(),(function fuck(){return \"Na\";})(),(function fuck(){return \"Fv\";})(),(function fuck(){return \"Xw\";})(),(func" ascii
    $s15 = "on fuck(){return \"IPu\";})(),(function fuck(){return \"Xw\";})(),(function fuck(){return \"Ar\";})(),(function fuck(){return \"" ascii
    $s16 = "eturn \"Wo\";})(),(function fuck(){return \"Av\";})(),(function fuck(){return \"ADy\";})(),(function fuck(){return \"IPu\";})()," ascii
    $s17 = "(),(function fuck(){return \"Xg\";})(),(function fuck(){return \"ZWu\";})(),(function fuck(){return \"Xw\";})(),(function fuck()" ascii

  condition:
    (uint16(0) == 0x2f0a and (8 of them)
    ) or (all of them)
}