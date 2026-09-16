rule TTP_XOR_QUAD_CurrentVersionRun_3258 {
  strings:
    $key_3258 = { 61 37 [2] 45 39 [2] 6e 15 [2] 40 37 [2] 54 2c [2] 5b 36 [2] 45 2b [2] 47 2a [2] 5c 2c [2] 40 2b [2] 5c 04 }

  condition:
    any of them
}