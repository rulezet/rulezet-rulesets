rule TTP_XOR_QUAD_CurrentVersionRun_16ed {
  strings:
    $key_16ed = { 45 82 [2] 61 8c [2] 4a a0 [2] 64 82 [2] 70 99 [2] 7f 83 [2] 61 9e [2] 63 9f [2] 78 99 [2] 64 9e [2] 78 b1 }

  condition:
    any of them
}