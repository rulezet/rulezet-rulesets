rule TTP_XOR_QUAD_CurrentVersionRun_1a51 {
  strings:
    $key_1a51 = { 49 3e [2] 6d 30 [2] 46 1c [2] 68 3e [2] 7c 25 [2] 73 3f [2] 6d 22 [2] 6f 23 [2] 74 25 [2] 68 22 [2] 74 0d }

  condition:
    any of them
}