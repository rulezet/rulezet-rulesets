rule _20160302_39a79c9c3891cfefe3596ecd14272490_20160302_41f4beea1cc7_915 {
  meta:
    description = "datamaliciousorder - from files 20160302_39a79c9c3891cfefe3596ecd14272490.js, 20160302_41f4beea1cc78d1834a1733a3b166988.js, 20160302_460c4660cb5f14a3eb9566fbdcf1167a.js, 20160302_6ff0f5a905db80c8ad640d28d370fc8d.js, 20160302_83a6644474bf85ec064c094838c7c8a7.js, 20160302_87150ff7882f1f2d7ca34e707d4c619e.js, 20160302_95212119830d40b4952f66b372283961.js, 20160302_9a7597c7bd35b1b203ba5fe6ace02e37.js, 20160302_cf75a729e9de16bf87423fb55fc42d4a.js, 20160302_df42795a3d0b1c139f6d9677f36b993c.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "68b0fe6292c36157ed30e8bf096c65d09b4ea5d98edc72091a7d0e1d86431c78"
    hash2       = "4a541dc75e217375ad75c16daecb24c79b54f1c0b0ec31fadd83ba1a06dee8c8"
    hash3       = "1b9fa42f465c88be8c59e5e5d83a1600aaa5c5b392d559fa23ddd8fc7cb2735b"
    hash4       = "7e2168dfe83678f1088cfb2b696a74313d27995a571731d6028bc8f870191a4f"
    hash5       = "d61432d159d4b03639bb88cba6967215f051fc4abaa21da1b6d8c3609fe55feb"
    hash6       = "1bd7d7434e5d7d5ab4e07d7751b008c2e08cdf8e5c14a6446ac60cfa86cf0719"
    hash7       = "65caa6d5ac33c9353d819932f4eee9a537f0183780a5cc43fa62c84dc280eb5b"
    hash8       = "71f29ae2d8fc2982c91c38ae314ecff4e6ea3cdaf5ac30d66e5d536b357c5203"
    hash9       = "6867a99b59ee4d4309a14af3202891a6f4eaf64c860e84f83cdc6bd4f3b820c7"
    hash10      = "74486488615a491cb1c855ac79684b8563f696d4e435ebd6727b5c7049daa72d"

  strings:
    $s1 = "// // Support: Android<4.1, IE<9  // Make sure we trim BOM and NBSP  rtrim = /^[\\s\\uFEFF\\xA0]+|[\\s\\uFEFF\\xA0]+$/g," fullword ascii
    $s2 = "            // // Get the Nth element in the matched element set OR  // Get the whole matched element set as a clean array  get:" ascii
    $s3 = "            // // Get the Nth element in the matched element set OR  // Get the whole matched element set as a clean array  get:" ascii
    $s4 = "            //   // Return just the one element from the set    ( num < 0 ? this[ num + this.length ] : this[ num ] ) :" fullword ascii
    $s5 = "            // // The current version of jQuery being used  jquery: version," fullword ascii
    $s6 = "// // Matches dashed string for camelizing  rmsPrefix = /^-ms-/,  rdashAlpha = /-([\\da-z])/gi," fullword ascii

  condition:
    (uint16(0) == 0x2f2f and (all of them)
    ) or (all of them)
}