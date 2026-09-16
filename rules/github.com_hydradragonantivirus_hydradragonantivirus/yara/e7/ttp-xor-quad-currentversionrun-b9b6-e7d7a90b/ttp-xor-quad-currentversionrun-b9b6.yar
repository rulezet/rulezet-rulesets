rule TTP_XOR_QUAD_CurrentVersionRun_b9b6 {
  strings:
    $key_b9b6 = { ea d9 [2] ce d7 [2] e5 fb [2] cb d9 [2] df c2 [2] d0 d8 [2] ce c5 [2] cc c4 [2] d7 c2 [2] cb c5 [2] d7 ea }

  condition:
    any of them
}