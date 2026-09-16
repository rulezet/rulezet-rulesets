rule TTP_XOR_QUAD_CurrentVersionRun_234c {
  strings:
    $key_234c = { 70 23 [2] 54 2d [2] 7f 01 [2] 51 23 [2] 45 38 [2] 4a 22 [2] 54 3f [2] 56 3e [2] 4d 38 [2] 51 3f [2] 4d 10 }

  condition:
    any of them
}