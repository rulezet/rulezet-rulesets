rule TTP_XOR_QUAD_CurrentVersionRun_7e2a {
  strings:
    $key_7e2a = { 2d 45 [2] 09 4b [2] 22 67 [2] 0c 45 [2] 18 5e [2] 17 44 [2] 09 59 [2] 0b 58 [2] 10 5e [2] 0c 59 [2] 10 76 }

  condition:
    any of them
}