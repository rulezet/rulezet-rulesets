rule TTP_XOR_QUAD_CurrentVersionRun_b9f7 {
  strings:
    $key_b9f7 = { ea 98 [2] ce 96 [2] e5 ba [2] cb 98 [2] df 83 [2] d0 99 [2] ce 84 [2] cc 85 [2] d7 83 [2] cb 84 [2] d7 ab }

  condition:
    any of them
}