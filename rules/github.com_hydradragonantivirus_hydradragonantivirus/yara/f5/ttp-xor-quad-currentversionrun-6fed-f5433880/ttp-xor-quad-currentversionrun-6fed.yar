rule TTP_XOR_QUAD_CurrentVersionRun_6fed {
  strings:
    $key_6fed = { 3c 82 [2] 18 8c [2] 33 a0 [2] 1d 82 [2] 09 99 [2] 06 83 [2] 18 9e [2] 1a 9f [2] 01 99 [2] 1d 9e [2] 01 b1 }

  condition:
    any of them
}