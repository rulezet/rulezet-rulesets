rule TTP_XOR_QUAD_CurrentVersionRun_1a6c {
  strings:
    $key_1a6c = { 49 03 [2] 6d 0d [2] 46 21 [2] 68 03 [2] 7c 18 [2] 73 02 [2] 6d 1f [2] 6f 1e [2] 74 18 [2] 68 1f [2] 74 30 }

  condition:
    any of them
}