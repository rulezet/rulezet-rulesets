rule TTP_XOR_QUAD_CurrentVersionRun_654c {
  strings:
    $key_654c = { 36 23 [2] 12 2d [2] 39 01 [2] 17 23 [2] 03 38 [2] 0c 22 [2] 12 3f [2] 10 3e [2] 0b 38 [2] 17 3f [2] 0b 10 }

  condition:
    any of them
}