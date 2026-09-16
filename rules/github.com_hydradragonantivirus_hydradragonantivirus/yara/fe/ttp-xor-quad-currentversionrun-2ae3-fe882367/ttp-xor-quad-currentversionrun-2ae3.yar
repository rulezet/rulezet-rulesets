rule TTP_XOR_QUAD_CurrentVersionRun_2ae3 {
  strings:
    $key_2ae3 = { 79 8c [2] 5d 82 [2] 76 ae [2] 58 8c [2] 4c 97 [2] 43 8d [2] 5d 90 [2] 5f 91 [2] 44 97 [2] 58 90 [2] 44 bf }

  condition:
    any of them
}