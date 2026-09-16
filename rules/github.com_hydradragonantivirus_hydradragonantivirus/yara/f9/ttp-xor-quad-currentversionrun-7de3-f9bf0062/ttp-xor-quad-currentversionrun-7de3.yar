rule TTP_XOR_QUAD_CurrentVersionRun_7de3 {
  strings:
    $key_7de3 = { 2e 8c [2] 0a 82 [2] 21 ae [2] 0f 8c [2] 1b 97 [2] 14 8d [2] 0a 90 [2] 08 91 [2] 13 97 [2] 0f 90 [2] 13 bf }

  condition:
    any of them
}