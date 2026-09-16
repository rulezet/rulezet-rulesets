rule TTP_XOR_QUAD_CurrentVersionRun_2b2a {
  strings:
    $key_2b2a = { 78 45 [2] 5c 4b [2] 77 67 [2] 59 45 [2] 4d 5e [2] 42 44 [2] 5c 59 [2] 5e 58 [2] 45 5e [2] 59 59 [2] 45 76 }

  condition:
    any of them
}