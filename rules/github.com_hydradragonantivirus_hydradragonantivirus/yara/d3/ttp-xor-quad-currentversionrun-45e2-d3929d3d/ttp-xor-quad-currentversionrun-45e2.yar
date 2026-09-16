rule TTP_XOR_QUAD_CurrentVersionRun_45e2 {
  strings:
    $key_45e2 = { 16 8d [2] 32 83 [2] 19 af [2] 37 8d [2] 23 96 [2] 2c 8c [2] 32 91 [2] 30 90 [2] 2b 96 [2] 37 91 [2] 2b be }

  condition:
    any of them
}