rule TTP_XOR_QUAD_CurrentVersionRun_2eed {
  strings:
    $key_2eed = { 7d 82 [2] 59 8c [2] 72 a0 [2] 5c 82 [2] 48 99 [2] 47 83 [2] 59 9e [2] 5b 9f [2] 40 99 [2] 5c 9e [2] 40 b1 }

  condition:
    any of them
}