rule TTP_XOR_QUAD_CurrentVersionRun_0be3 {
  strings:
    $key_0be3 = { 58 8c [2] 7c 82 [2] 57 ae [2] 79 8c [2] 6d 97 [2] 62 8d [2] 7c 90 [2] 7e 91 [2] 65 97 [2] 79 90 [2] 65 bf }

  condition:
    any of them
}