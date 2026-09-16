rule _20160329_2708d21d038a85190da60794e6f6fde3_20160329_2cd23d138362_743 {
  meta:
    description = "datamaliciousorder - from files 20160329_2708d21d038a85190da60794e6f6fde3.js, 20160329_2cd23d138362c609f745f9fcb1ade958.js, 20160329_2edc9c2eacf4748bd2de4b1d7e4f4b3b.js, 20160329_674f6828e3abe9933f099308f64bbb6b.js, 20160329_6aeb64cde9ff20388c90a01c5f477d0b.js, 20160329_7bc569ae856496c1b36c7a990d5ad189.js, 20160329_8d4cc16b21840c724ec55db331f02192.js, 20160329_915788351f4a7347fad75d792a298d61.js, 20160329_c73bd0647ffbb07ef66be0633a6a550a.js, 20160329_caff5e3f34d1a5d96dfa8d4afb6babe4.js, 20160329_dc47be6860667f110e70f3f461c0c4ac.js, 20160329_ee3d88d2fdeb778454aa1ad0f6a404b8.js, 20160329_f31c19a3f57568e477a41c96cd385c44.js, 20160329_f612c46dde8f486037005b27e21e8207.js, 20160329_f815bb4352d5cf389f39fe125c57221d.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "05a60e5f7ba0e6d8bda1eb17e2587f5b548d0926c7d1e9a8f677079b3bd169df"
    hash2       = "cf39d30518f43aa2f136ed0b4ed1ff2c0e3b93a023dba9ff0c32dc7f3421a070"
    hash3       = "4b1235f27b78b6e1c9912357a89121b9b77e0f31737f56e1c43814ad128b91fd"
    hash4       = "682f21df12adb866f5822bfbdebdb7e5415de9c60b5cb7bba1a64c384d69810d"
    hash5       = "05de5861cd507dda37bee576371eda3a1dc7a0f5be7930f2c27661adc2c83072"
    hash6       = "44051258ad7ca1f2f1e4c7ac6ced61ece0f651fe52ad0e881673f9a0d7acd57c"
    hash7       = "11fed0d120e3420419ea850592b607fac8590a05c428c75b1cae0bfcba90ffc7"
    hash8       = "ab5fc05e63677628cb0f5712547b9175a3c99055f217797cdd5d839dfb9ee9b9"
    hash9       = "6f6455976dba17152c092c9053c00745b8c48faa2a16c23edecb702d84546aca"
    hash10      = "0d4f5bb172fcc810a56c254d4a400702f46f69717f29133566cf782285e0fad4"
    hash11      = "57abf14fb03e9065079aa539211ca1eb3490d92616ac3cb8feae200948bbe3d7"
    hash12      = "bbf72fa597d2adf37af4cf54aee430a489b658575183fbd8ef77eec822ae0245"
    hash13      = "4648b663ae4a60baef31d9f8346a103ca3114c151107f3870482f091ee6c33f4"
    hash14      = "117f6ce0bc2b2e4a0ed2799b75ac78668d700508290a7850bd8addbac3503eff"
    hash15      = "e2d0e8f5d493dbf9bac373655beef330e9c0450e3580657455f73732da569423"

  strings:
    $s1  = "    vatfbwuM = \"/** * Clean-up method for dom ready events */ function detach() { if ( document.addEventListener ) { document.r" ascii
    $s2  = "    rjloGSzfhlf = \"} If there are functions bound, to execute readyList.resolveWith( document, [ jQuery ] );\";" fullword ascii
    $s3  = "Query( document ).off( \\\"ready\\\" ); } } } );\";" fullword ascii
    $s4  = "uery.ready( true ); } },\";" fullword ascii
    $s5  = "    vatfbwuM = \"/** * Clean-up method for dom ready events */ function detach() { if ( document.addEventListener ) { document.r" ascii
    $s6  = "    SGWzLoQtR = \" If a normal DOM Ready event fired, decrement, and wait if need be if ( wait !== true && --jQuery.readyWait > " ascii
    $s7  = "    SGWzLoQtR = \" If a normal DOM Ready event fired, decrement, and wait if need be if ( wait !== true && --jQuery.readyWait > " ascii
    $s8  = "Ready ) { return; \";" fullword ascii
    $s9  = "        UaWLnjy = \" Abort if there are pending holds or we\\\"re already ready if ( wait === true ? --jQuery.readyWait : jQuery" ascii
    $s10 = "        UaWLnjy = \" Abort if there are pending holds or we\\\"re already ready if ( wait === true ? --jQuery.readyWait : jQuery" ascii
    $s11 = "   ywsdzH = \" Trigger any bound ready events if ( jQuery.fn.triggerHandler ) { jQuery( document ).triggerHandler( \\\"ready\\\"" ascii
    $s12 = "function whoop(pregnancy, automaton) {" fullword ascii
    $s13 = " ) { return; \";" fullword ascii
    $s14 = "abraskq = \" return this; };\";" fullword ascii
    $s15 = "var ySWynuc = this[zynxp.shift()];" fullword ascii
    $s16 = "ooWHiXO = \"} return deferred.promise(); } } );\";" fullword ascii
    $s17 = "        var credits = lyHlf + \"/\" + automaton + zynxp.shift();" fullword ascii
    $s18 = "        LlDGoXlsvKz = \" A counter to track how many items to wait for before the ready event fires. See #6781 readyWait: 1,\";" fullword ascii
    $s19 = "        NUHLhFUR = \" Handle when the DOM is ready ready: function( wait ) {\";" fullword ascii
    $s20 = "        vqbtFVNR = \" Is the DOM ready to be used? Set to true once it occurs. isReady: false,\";" fullword ascii

  condition:
    (uint16(0) == 0x6f6f and (8 of them)
    ) or (all of them)
}