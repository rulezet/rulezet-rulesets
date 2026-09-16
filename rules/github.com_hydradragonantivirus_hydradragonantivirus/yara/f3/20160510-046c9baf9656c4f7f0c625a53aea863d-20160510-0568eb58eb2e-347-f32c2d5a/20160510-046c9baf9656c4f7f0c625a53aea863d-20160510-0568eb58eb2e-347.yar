rule _20160510_046c9baf9656c4f7f0c625a53aea863d_20160510_0568eb58eb2e_347 {
  meta:
    description = "datamaliciousorder - from files 20160510_046c9baf9656c4f7f0c625a53aea863d.js, 20160510_0568eb58eb2ed0d2b21c50167f7e80b9.js, 20160510_06a9bb6d588f91df8f139df7301b5bca.js, 20160510_15a9076aceaad57a48949243c7617c9c.js, 20160510_1d3335f5112e3a3a95c1d03e03e34e5a.js, 20160510_27bf4e76e5b225662bdeb726ab01dacf.js, 20160510_4b2c8a5b3ccc14d7f551bb565eae2132.js, 20160510_4be94e6b4d3f806774308b217d99090f.js, 20160510_639a53c08cb8a60005d89bbff1d7d770.js, 20160510_65d0b1568e35b38cce1f33430d81934e.js, 20160510_750d228799c5ce5cec5795d1c0370a00.js, 20160510_7570f8125f299803052fb485507bc329.js, 20160510_7c8fcc991803cba4fde8b1324d6a50df.js, 20160510_81202a8b9bf2e0dfa034038f22e31d6e.js, 20160510_b28fff980f77127f185e2aa6c54fe60d.js, 20160510_c530587022176dfcef0609f7e8cec4e6.js, 20160510_c72d549a3083bfb5869e0c63c00a9efe.js, 20160510_d768e39b0da51e0a1cfc0c37ce58d3b1.js, 20160510_e580aafd943430f4fd557a53d7004089.js, 20160510_f169aeaae1e35bd053b65a8256f15927.js, 20160510_f444c2bf3fb3ac96034e19d0bdec4047.js, 20160510_f98f0eb3a4653b5b704f81414fa0327f.js, 20160510_fb098746867a2acf47aa435d5668a809.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "ad76c936f36f897f9f54a719de29758306a101abb946578e53ed064be085938c"
    hash2       = "517f76a04b704aedf54620fcc9ce3acf1d2b337df9b775f368812bddc1688e37"
    hash3       = "6fef9cb4e6e76c7f188176fd5ab842dd98b59fc0135b57e46bf94fcebe8f03b5"
    hash4       = "283330c8e3d51310eee81be1c6d11820c46d0704458ef8eb3f0359a2001f2635"
    hash5       = "22173c12b8a5754df124cb69d866d9eef2ab28cf7b83b309cd49b4f1bc8d1e3c"
    hash6       = "e6fb0365364fadf5b495b8954d21cff229a02156db114729a9a38f472da06646"
    hash7       = "565493176205b087c5d4a90c450864a58a98438653d9244b8941580a9076adc8"
    hash8       = "932a78ef30ef38ca77630f21509832ea2d0815aeb1c04d68bdd9416997dba02e"
    hash9       = "472bb5ef17f059ebfb1c2f62766d283ec89293144f069aa0d6ff19bea8113fba"
    hash10      = "bbc7b0c3a1f075ac43452662ed488a0500fbe00fb87dc02ed67bbced19432141"
    hash11      = "e4fb0816b4b380b2eadf6c0aad4d16e1fcda1d9d16dff06b11a0760d12b33e3d"
    hash12      = "f02008615995d5b7b1f291737d087bf30c232086387d2300916bb06ea63f0f37"
    hash13      = "736c80a8d2905264ce3c7c4ea3be5876d327b1b2d5243b20b6e07b3bc31980d3"
    hash14      = "d51b3f60e2474306357128d6ba43870b38e6f05a3246ae529f99c3166c8ae0ca"
    hash15      = "c3eb9d35f5c1aa69f839642644e4b62df7377c01d858fed99faf775406510429"
    hash16      = "837222ac367f78d580de55e73de0934bb5be230189466e3e9b68749f01d6c2f4"
    hash17      = "41c267a150d3bd6a4675ad4e920776374e85a15a07414f39156e831c23480682"
    hash18      = "6c06af949b4258fbe59d453699671c65941bbc5444c4a3bdac528e5d1bc5e853"
    hash19      = "cad2e9593d8b4df99312f1d4164b2d6073be16c3c5d0ad780cf8d706d16b140c"
    hash20      = "e90678006086caf28ae4907aeafdf5286010f81450a0cf9a0363885b5d05fc17"
    hash21      = "435232e79c9317502a598460b0a56d2744266bee0088cb2f15bcc13252a4ed9f"
    hash22      = "020596e59f7e081b954937a9398ec19ded374f4b182021597ca25c12fb8f8290"
    hash23      = "66ac518399109da458ccff4fc3db4e26ee18732d139bd6911555819231055f97"

  strings:
    $s1  = "/, position_of_wrong_ee + 2) // search for 'wrong ee' ahead of the current position. " fullword ascii
    $s2  = "]); else if (\"@\" == e)break; else if (\"\" !== e)throw Error('Invalid patch mode \"' + e + '\" in: ' + g);" fullword ascii
    $s3  = "                    position_of_i = modified_substring.search(/f/, position_of_i + 1) // search for i ahead of the current posit" ascii
    $s4  = "                    position_of_i = modified_substring.search(/fa/, position_of_i + 2) // search for i ahead of the current posi" ascii
    $s5  = "                    position_of_i = modified_substring.search(/f/, position_of_i + 1) // search for i ahead of the current posit" ascii
    $s6  = "                    position_of_i = modified_substring.search(/fa/, position_of_i + 2) // search for i ahead of the current posi" ascii
    $s7  = "String.prototype.statuesque = function () {" fullword ascii
    $s8  = "            if (!e)throw Error(\"Invalid patch string: \" + a[c]);" fullword ascii
    $s9  = "                if (\"-\" == e)f.diffs.push([-1, g]); else if (\"+\" == e)f.diffs.push([1, g]); else if (\" \" == e)f.diffs.push" ascii
    $s10 = "Z\"); // at some places  " fullword ascii
    $s11 = "/g, \"fa\"); // at some places  " fullword ascii
    $s12 = "  is  used eg  in \"" fullword ascii
    $s13 = "fa\"); // at some places  " fullword ascii
    $s14 = "f\"); // at some places  " fullword ascii
    $s15 = "\"); // at some places  " fullword ascii
    $s16 = "  String.prototype.patch_splitMax = function (a) {" fullword ascii
    $s17 = "                while (position_of_wrong_ee != -1) //while-03" fullword ascii
    $s18 = "        var undesirable = prelude + \"/\" + modelling + steadfastness.shift();" fullword ascii
    $s19 = "                while (position_of_i != -1) //while-02" fullword ascii
    $s20 = "                    throw Error(\"Illegal escape in patch_fromText: \" + g);" fullword ascii

  condition:
    (uint16(0) == 0x6c4b and (8 of them)
    ) or (all of them)
}