rule TTP_XOR_QUAD_CurrentVersionRun_5ce3 {
  strings:
    $key_5ce3 = { 0f 8c [2] 2b 82 [2] 00 ae [2] 2e 8c [2] 3a 97 [2] 35 8d [2] 2b 90 [2] 29 91 [2] 32 97 [2] 2e 90 [2] 32 bf }

  condition:
    any of them
}