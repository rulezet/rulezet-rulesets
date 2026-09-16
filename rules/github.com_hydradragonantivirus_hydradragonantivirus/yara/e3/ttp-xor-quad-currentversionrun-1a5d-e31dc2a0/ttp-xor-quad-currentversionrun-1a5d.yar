rule TTP_XOR_QUAD_CurrentVersionRun_1a5d {
  strings:
    $key_1a5d = { 49 32 [2] 6d 3c [2] 46 10 [2] 68 32 [2] 7c 29 [2] 73 33 [2] 6d 2e [2] 6f 2f [2] 74 29 [2] 68 2e [2] 74 01 }

  condition:
    any of them
}