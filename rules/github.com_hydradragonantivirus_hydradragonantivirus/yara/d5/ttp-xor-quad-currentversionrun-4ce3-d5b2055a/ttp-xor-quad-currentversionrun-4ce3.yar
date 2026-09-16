rule TTP_XOR_QUAD_CurrentVersionRun_4ce3 {
  strings:
    $key_4ce3 = { 1f 8c [2] 3b 82 [2] 10 ae [2] 3e 8c [2] 2a 97 [2] 25 8d [2] 3b 90 [2] 39 91 [2] 22 97 [2] 3e 90 [2] 22 bf }

  condition:
    any of them
}