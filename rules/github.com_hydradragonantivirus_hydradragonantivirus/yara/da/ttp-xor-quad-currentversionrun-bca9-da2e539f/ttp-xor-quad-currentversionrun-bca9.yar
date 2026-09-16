rule TTP_XOR_QUAD_CurrentVersionRun_bca9 {
  strings:
    $key_bca9 = { ef c6 [2] cb c8 [2] e0 e4 [2] ce c6 [2] da dd [2] d5 c7 [2] cb da [2] c9 db [2] d2 dd [2] ce da [2] d2 f5 }

  condition:
    any of them
}