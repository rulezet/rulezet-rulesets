rule TTP_XOR_QUAD_CurrentVersionRun_45fc {
  strings:
    $key_45fc = { 16 93 [2] 32 9d [2] 19 b1 [2] 37 93 [2] 23 88 [2] 2c 92 [2] 32 8f [2] 30 8e [2] 2b 88 [2] 37 8f [2] 2b a0 }

  condition:
    any of them
}