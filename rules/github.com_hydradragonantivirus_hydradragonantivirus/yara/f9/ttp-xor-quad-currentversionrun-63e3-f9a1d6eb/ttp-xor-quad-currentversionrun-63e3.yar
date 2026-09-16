rule TTP_XOR_QUAD_CurrentVersionRun_63e3 {
  strings:
    $key_63e3 = { 30 8c [2] 14 82 [2] 3f ae [2] 11 8c [2] 05 97 [2] 0a 8d [2] 14 90 [2] 16 91 [2] 0d 97 [2] 11 90 [2] 0d bf }

  condition:
    any of them
}