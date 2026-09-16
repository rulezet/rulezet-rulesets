rule _20160921_2a4687842acdb7843675f91c11ae7986_20160921_4bad0ae96eb9_4788 {
  meta:
    description = "datamaliciousorder - from files 20160921_2a4687842acdb7843675f91c11ae7986.js, 20160921_4bad0ae96eb9fc3a1c603846a44ffe13.js, 20160921_73310531aa4a1df7337a6ef42003ce5e.js, 20160921_8be5b3aac0a2f47acb168b56c6f880bf.js, 20160921_97811319fb50bbd834b521ddcbb35712.js, 20160921_ce3c0604d52e9dc9119cefedfee34385.js, 20160921_e53844f4bb18305322896332fbd017e8.js, 20160921_e6771cfa257410eb61913de76cb777a8.js, 20160921_ee6d5c7dc2c03b89ea5ef53aa0c676a1.js, 20160921_f69cc523f43841dbc6246209e09d2b8b.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "0b483b885082d284a148ab2a97b57881cd387b85b477025ad126d680e158bc62"
    hash2       = "a99f235f58613323f5c58def3503d47959f4a77f0697e30c75b6d221c4b40806"
    hash3       = "c1f6942ac4bb494bebef47181bbb9c9fe04d3d155e4bc18b2ff21e74c6592f78"
    hash4       = "344d7dd8865545f9f4c1045a85547b4140c66621aeedeb02bf60ff4598ff6930"
    hash5       = "4105b34a1f3797b1fc5f9b5d7f49d995c2796d5876f07b87b344f6c7e8c0625e"
    hash6       = "27a20a400d7aa13737d230acf36a2170494c7da92e72552775d19562ba331fdc"
    hash7       = "b8484bab412a47fffb0a694f32ca5de3480841bd1c0806d0a7e6e86dfd21de6c"
    hash8       = "009074e75815902f1e36daa21c179598b761767cd8d92eb363f3541838abdbfe"
    hash9       = "ddd3db3929119812b70ad9f62bd3187b6108d24999c41a8ff5390bc9a60387a3"
    hash10      = "82ee8104aecfd309a85de470b641e14f7ef67f3b3ec968ce41eade759620fd53"

  strings:
    $s1 = "f\";})(),(function fuck(){return \"Fv\";})(),(function fuck(){return \"XHj\";})(),(function fuck(){return \"Fv\";})(),(function " ascii
    $s2 = "),(function fuck(){return \"Na\";})(),(function fuck(){return \"IOs\";})(),(function fuck(){return \"Ik\";})(),(function fuck(){" ascii
    $s3 = "uck(){return \"ZVi\";})(),(function fuck(){return \"Dc\";})(),(function fuck(){return \"Za\";})(),(function fuck(){return \"Mw\"" ascii
    $s4 = "unction fuck(){return \"UXf\";})(),(function fuck(){return \"Sx\";})(),(function fuck(){return \"Xg\";})(),(function fuck(){retu" ascii
    $s5 = " \"UXf\";})(),(function fuck(){return \"KVh\";})(),(function fuck(){return \"ZWu\";})(),(function fuck(){return \"UXf\";})(),(fu" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}