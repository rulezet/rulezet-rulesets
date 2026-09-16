rule TTP_XOR_QUAD_CurrentVersionRun_28e3 {
  strings:
    $key_28e3 = { 7b 8c [2] 5f 82 [2] 74 ae [2] 5a 8c [2] 4e 97 [2] 41 8d [2] 5f 90 [2] 5d 91 [2] 46 97 [2] 5a 90 [2] 46 bf }

  condition:
    any of them
}