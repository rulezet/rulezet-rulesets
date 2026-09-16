rule TTP_XOR_QUAD_CurrentVersionRun_0958 {
  strings:
    $key_0958 = { 5a 37 [2] 7e 39 [2] 55 15 [2] 7b 37 [2] 6f 2c [2] 60 36 [2] 7e 2b [2] 7c 2a [2] 67 2c [2] 7b 2b [2] 67 04 }

  condition:
    any of them
}