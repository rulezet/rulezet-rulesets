rule TTP_XOR_QUAD_CurrentVersionRun_4b1c {
  strings:
    $key_4b1c = { 18 73 [2] 3c 7d [2] 17 51 [2] 39 73 [2] 2d 68 [2] 22 72 [2] 3c 6f [2] 3e 6e [2] 25 68 [2] 39 6f [2] 25 40 }

  condition:
    any of them
}