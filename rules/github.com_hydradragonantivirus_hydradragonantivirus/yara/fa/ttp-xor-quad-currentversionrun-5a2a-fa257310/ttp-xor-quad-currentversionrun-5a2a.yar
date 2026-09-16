rule TTP_XOR_QUAD_CurrentVersionRun_5a2a {
  strings:
    $key_5a2a = { 09 45 [2] 2d 4b [2] 06 67 [2] 28 45 [2] 3c 5e [2] 33 44 [2] 2d 59 [2] 2f 58 [2] 34 5e [2] 28 59 [2] 34 76 }

  condition:
    any of them
}