rule TTP_XOR_QUAD_CurrentVersionRun_b9b5 {
  strings:
    $key_b9b5 = { ea da [2] ce d4 [2] e5 f8 [2] cb da [2] df c1 [2] d0 db [2] ce c6 [2] cc c7 [2] d7 c1 [2] cb c6 [2] d7 e9 }

  condition:
    any of them
}