rule TTP_XOR_QUAD_CurrentVersionRun_1a01 {
  strings:
    $key_1a01 = { 49 6e [2] 6d 60 [2] 46 4c [2] 68 6e [2] 7c 75 [2] 73 6f [2] 6d 72 [2] 6f 73 [2] 74 75 [2] 68 72 [2] 74 5d }

  condition:
    any of them
}