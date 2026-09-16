rule TTP_XOR_QUAD_CurrentVersionRun_5a1c {
  strings:
    $key_5a1c = { 09 73 [2] 2d 7d [2] 06 51 [2] 28 73 [2] 3c 68 [2] 33 72 [2] 2d 6f [2] 2f 6e [2] 34 68 [2] 28 6f [2] 34 40 }

  condition:
    any of them
}