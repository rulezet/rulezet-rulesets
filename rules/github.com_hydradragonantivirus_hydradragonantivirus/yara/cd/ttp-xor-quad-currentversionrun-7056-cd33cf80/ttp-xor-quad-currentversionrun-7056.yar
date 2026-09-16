rule TTP_XOR_QUAD_CurrentVersionRun_7056 {
  strings:
    $key_7056 = { 23 39 [2] 07 37 [2] 2c 1b [2] 02 39 [2] 16 22 [2] 19 38 [2] 07 25 [2] 05 24 [2] 1e 22 [2] 02 25 [2] 1e 0a }

  condition:
    any of them
}