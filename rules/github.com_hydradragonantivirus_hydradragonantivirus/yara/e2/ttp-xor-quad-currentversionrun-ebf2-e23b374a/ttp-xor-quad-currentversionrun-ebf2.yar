rule TTP_XOR_QUAD_CurrentVersionRun_ebf2 {
  strings:
    $key_ebf2 = { b8 9d [2] 9c 93 [2] b7 bf [2] 99 9d [2] 8d 86 [2] 82 9c [2] 9c 81 [2] 9e 80 [2] 85 86 [2] 99 81 [2] 85 ae }

  condition:
    any of them
}