rule TTP_XOR_QUAD_CurrentVersionRun_3b2a {
  strings:
    $key_3b2a = { 68 45 [2] 4c 4b [2] 67 67 [2] 49 45 [2] 5d 5e [2] 52 44 [2] 4c 59 [2] 4e 58 [2] 55 5e [2] 49 59 [2] 55 76 }

  condition:
    any of them
}