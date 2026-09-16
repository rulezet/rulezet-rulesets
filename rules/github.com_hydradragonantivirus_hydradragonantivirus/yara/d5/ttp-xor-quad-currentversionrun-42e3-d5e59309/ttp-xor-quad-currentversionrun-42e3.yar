rule TTP_XOR_QUAD_CurrentVersionRun_42e3 {
  strings:
    $key_42e3 = { 11 8c [2] 35 82 [2] 1e ae [2] 30 8c [2] 24 97 [2] 2b 8d [2] 35 90 [2] 37 91 [2] 2c 97 [2] 30 90 [2] 2c bf }

  condition:
    any of them
}