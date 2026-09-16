rule TTP_XOR_QUAD_CurrentVersionRun_72e3 {
  strings:
    $key_72e3 = { 21 8c [2] 05 82 [2] 2e ae [2] 00 8c [2] 14 97 [2] 1b 8d [2] 05 90 [2] 07 91 [2] 1c 97 [2] 00 90 [2] 1c bf }

  condition:
    any of them
}