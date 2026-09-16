rule TTP_XOR_QUAD_CurrentVersionRun_6d2a {
  strings:
    $key_6d2a = { 3e 45 [2] 1a 4b [2] 31 67 [2] 1f 45 [2] 0b 5e [2] 04 44 [2] 1a 59 [2] 18 58 [2] 03 5e [2] 1f 59 [2] 03 76 }

  condition:
    any of them
}