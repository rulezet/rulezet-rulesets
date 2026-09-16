rule TTP_XOR_QUAD_CurrentVersionRun_43e3 {
  strings:
    $key_43e3 = { 10 8c [2] 34 82 [2] 1f ae [2] 31 8c [2] 25 97 [2] 2a 8d [2] 34 90 [2] 36 91 [2] 2d 97 [2] 31 90 [2] 2d bf }

  condition:
    any of them
}