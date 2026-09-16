rule TTP_XOR_QUAD_CurrentVersionRun_22e3 {
  strings:
    $key_22e3 = { 71 8c [2] 55 82 [2] 7e ae [2] 50 8c [2] 44 97 [2] 4b 8d [2] 55 90 [2] 57 91 [2] 4c 97 [2] 50 90 [2] 4c bf }

  condition:
    any of them
}