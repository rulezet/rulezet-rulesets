rule TTP_XOR_QUAD_CurrentVersionRun_1de3 {
  strings:
    $key_1de3 = { 4e 8c [2] 6a 82 [2] 41 ae [2] 6f 8c [2] 7b 97 [2] 74 8d [2] 6a 90 [2] 68 91 [2] 73 97 [2] 6f 90 [2] 73 bf }

  condition:
    any of them
}