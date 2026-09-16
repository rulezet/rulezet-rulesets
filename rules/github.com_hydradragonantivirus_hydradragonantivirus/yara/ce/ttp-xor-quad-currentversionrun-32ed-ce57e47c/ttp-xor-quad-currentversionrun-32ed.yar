rule TTP_XOR_QUAD_CurrentVersionRun_32ed {
  strings:
    $key_32ed = { 61 82 [2] 45 8c [2] 6e a0 [2] 40 82 [2] 54 99 [2] 5b 83 [2] 45 9e [2] 47 9f [2] 5c 99 [2] 40 9e [2] 5c b1 }

  condition:
    any of them
}