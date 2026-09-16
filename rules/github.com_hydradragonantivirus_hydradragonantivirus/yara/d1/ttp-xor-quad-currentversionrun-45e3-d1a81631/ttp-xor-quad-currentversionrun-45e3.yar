rule TTP_XOR_QUAD_CurrentVersionRun_45e3 {
  strings:
    $key_45e3 = { 16 8c [2] 32 82 [2] 19 ae [2] 37 8c [2] 23 97 [2] 2c 8d [2] 32 90 [2] 30 91 [2] 2b 97 [2] 37 90 [2] 2b bf }

  condition:
    any of them
}