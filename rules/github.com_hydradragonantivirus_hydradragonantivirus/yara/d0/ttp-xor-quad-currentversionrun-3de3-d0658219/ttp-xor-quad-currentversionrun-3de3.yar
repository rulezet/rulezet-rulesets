rule TTP_XOR_QUAD_CurrentVersionRun_3de3 {
  strings:
    $key_3de3 = { 6e 8c [2] 4a 82 [2] 61 ae [2] 4f 8c [2] 5b 97 [2] 54 8d [2] 4a 90 [2] 48 91 [2] 53 97 [2] 4f 90 [2] 53 bf }

  condition:
    any of them
}