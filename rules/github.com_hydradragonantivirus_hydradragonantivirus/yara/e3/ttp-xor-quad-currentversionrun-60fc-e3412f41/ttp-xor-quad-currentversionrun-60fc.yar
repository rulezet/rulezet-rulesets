rule TTP_XOR_QUAD_CurrentVersionRun_60fc {
  strings:
    $key_60fc = { 33 93 [2] 17 9d [2] 3c b1 [2] 12 93 [2] 06 88 [2] 09 92 [2] 17 8f [2] 15 8e [2] 0e 88 [2] 12 8f [2] 0e a0 }

  condition:
    any of them
}