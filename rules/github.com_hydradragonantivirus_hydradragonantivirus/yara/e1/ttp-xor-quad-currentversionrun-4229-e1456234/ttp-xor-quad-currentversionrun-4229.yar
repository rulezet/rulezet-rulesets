rule TTP_XOR_QUAD_CurrentVersionRun_4229 {
  strings:
    $key_4229 = { 11 46 [2] 35 48 [2] 1e 64 [2] 30 46 [2] 24 5d [2] 2b 47 [2] 35 5a [2] 37 5b [2] 2c 5d [2] 30 5a [2] 2c 75 }

  condition:
    any of them
}