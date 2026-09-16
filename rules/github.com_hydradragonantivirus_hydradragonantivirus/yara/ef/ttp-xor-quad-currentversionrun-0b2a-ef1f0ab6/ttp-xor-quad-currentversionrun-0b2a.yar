rule TTP_XOR_QUAD_CurrentVersionRun_0b2a {
  strings:
    $key_0b2a = { 58 45 [2] 7c 4b [2] 57 67 [2] 79 45 [2] 6d 5e [2] 62 44 [2] 7c 59 [2] 7e 58 [2] 65 5e [2] 79 59 [2] 65 76 }

  condition:
    any of them
}