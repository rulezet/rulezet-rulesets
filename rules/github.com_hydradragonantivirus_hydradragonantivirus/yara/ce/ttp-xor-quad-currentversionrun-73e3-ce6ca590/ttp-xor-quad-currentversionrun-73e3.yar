rule TTP_XOR_QUAD_CurrentVersionRun_73e3 {
  strings:
    $key_73e3 = { 20 8c [2] 04 82 [2] 2f ae [2] 01 8c [2] 15 97 [2] 1a 8d [2] 04 90 [2] 06 91 [2] 1d 97 [2] 01 90 [2] 1d bf }

  condition:
    any of them
}