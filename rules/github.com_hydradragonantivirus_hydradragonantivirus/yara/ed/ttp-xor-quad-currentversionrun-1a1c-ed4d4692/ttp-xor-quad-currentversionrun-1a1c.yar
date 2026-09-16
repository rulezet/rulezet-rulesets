rule TTP_XOR_QUAD_CurrentVersionRun_1a1c {
  strings:
    $key_1a1c = { 49 73 [2] 6d 7d [2] 46 51 [2] 68 73 [2] 7c 68 [2] 73 72 [2] 6d 6f [2] 6f 6e [2] 74 68 [2] 68 6f [2] 74 40 }

  condition:
    any of them
}