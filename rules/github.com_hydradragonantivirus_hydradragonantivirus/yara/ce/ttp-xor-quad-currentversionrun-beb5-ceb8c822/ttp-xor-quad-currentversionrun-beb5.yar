rule TTP_XOR_QUAD_CurrentVersionRun_beb5 {
  strings:
    $key_beb5 = { ed da [2] c9 d4 [2] e2 f8 [2] cc da [2] d8 c1 [2] d7 db [2] c9 c6 [2] cb c7 [2] d0 c1 [2] cc c6 [2] d0 e9 }

  condition:
    any of them
}