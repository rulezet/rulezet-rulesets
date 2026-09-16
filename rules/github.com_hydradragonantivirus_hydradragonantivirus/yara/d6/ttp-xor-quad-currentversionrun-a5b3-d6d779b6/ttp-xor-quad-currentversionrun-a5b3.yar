rule TTP_XOR_QUAD_CurrentVersionRun_a5b3 {
  strings:
    $key_a5b3 = { f6 dc [2] d2 d2 [2] f9 fe [2] d7 dc [2] c3 c7 [2] cc dd [2] d2 c0 [2] d0 c1 [2] cb c7 [2] d7 c0 [2] cb ef }

  condition:
    any of them
}