rule TTP_XOR_QUAD_CurrentVersionRun_102a {
  strings:
    $key_102a = { 43 45 [2] 67 4b [2] 4c 67 [2] 62 45 [2] 76 5e [2] 79 44 [2] 67 59 [2] 65 58 [2] 7e 5e [2] 62 59 [2] 7e 76 }

  condition:
    any of them
}