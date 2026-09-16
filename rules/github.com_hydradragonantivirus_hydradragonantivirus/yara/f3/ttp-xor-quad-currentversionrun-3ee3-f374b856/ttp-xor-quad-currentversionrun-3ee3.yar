rule TTP_XOR_QUAD_CurrentVersionRun_3ee3 {
  strings:
    $key_3ee3 = { 6d 8c [2] 49 82 [2] 62 ae [2] 4c 8c [2] 58 97 [2] 57 8d [2] 49 90 [2] 4b 91 [2] 50 97 [2] 4c 90 [2] 50 bf }

  condition:
    any of them
}