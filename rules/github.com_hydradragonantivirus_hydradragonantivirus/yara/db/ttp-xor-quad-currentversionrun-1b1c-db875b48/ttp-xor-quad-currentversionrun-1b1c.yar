rule TTP_XOR_QUAD_CurrentVersionRun_1b1c {
  strings:
    $key_1b1c = { 48 73 [2] 6c 7d [2] 47 51 [2] 69 73 [2] 7d 68 [2] 72 72 [2] 6c 6f [2] 6e 6e [2] 75 68 [2] 69 6f [2] 75 40 }

  condition:
    any of them
}