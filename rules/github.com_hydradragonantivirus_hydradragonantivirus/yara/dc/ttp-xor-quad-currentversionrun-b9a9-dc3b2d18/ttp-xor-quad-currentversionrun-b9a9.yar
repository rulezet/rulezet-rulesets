rule TTP_XOR_QUAD_CurrentVersionRun_b9a9 {
  strings:
    $key_b9a9 = { ea c6 [2] ce c8 [2] e5 e4 [2] cb c6 [2] df dd [2] d0 c7 [2] ce da [2] cc db [2] d7 dd [2] cb da [2] d7 f5 }

  condition:
    any of them
}