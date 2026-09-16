rule TTP_XOR_QUAD_CurrentVersionRun_4ee3 {
  strings:
    $key_4ee3 = { 1d 8c [2] 39 82 [2] 12 ae [2] 3c 8c [2] 28 97 [2] 27 8d [2] 39 90 [2] 3b 91 [2] 20 97 [2] 3c 90 [2] 20 bf }

  condition:
    any of them
}