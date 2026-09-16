rule TTP_XOR_QUAD_CurrentVersionRun_19ed {
  strings:
    $key_19ed = { 4a 82 [2] 6e 8c [2] 45 a0 [2] 6b 82 [2] 7f 99 [2] 70 83 [2] 6e 9e [2] 6c 9f [2] 77 99 [2] 6b 9e [2] 77 b1 }

  condition:
    any of them
}