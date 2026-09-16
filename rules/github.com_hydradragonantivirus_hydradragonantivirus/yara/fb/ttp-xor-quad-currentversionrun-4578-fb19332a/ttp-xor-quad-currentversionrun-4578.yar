rule TTP_XOR_QUAD_CurrentVersionRun_4578 {
  strings:
    $key_4578 = { 16 17 [2] 32 19 [2] 19 35 [2] 37 17 [2] 23 0c [2] 2c 16 [2] 32 0b [2] 30 0a [2] 2b 0c [2] 37 0b [2] 2b 24 }

  condition:
    any of them
}