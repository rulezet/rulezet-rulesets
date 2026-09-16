rule TTP_XOR_QUAD_CurrentVersionRun_1afd {
  strings:
    $key_1afd = { 49 92 [2] 6d 9c [2] 46 b0 [2] 68 92 [2] 7c 89 [2] 73 93 [2] 6d 8e [2] 6f 8f [2] 74 89 [2] 68 8e [2] 74 a1 }

  condition:
    any of them
}