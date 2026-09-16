rule TTP_XOR_QUAD_CurrentVersionRun_70e3 {
  strings:
    $key_70e3 = { 23 8c [2] 07 82 [2] 2c ae [2] 02 8c [2] 16 97 [2] 19 8d [2] 07 90 [2] 05 91 [2] 1e 97 [2] 02 90 [2] 1e bf }

  condition:
    any of them
}