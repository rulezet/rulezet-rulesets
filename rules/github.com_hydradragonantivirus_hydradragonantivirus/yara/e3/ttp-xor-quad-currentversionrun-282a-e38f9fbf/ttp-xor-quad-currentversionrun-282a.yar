rule TTP_XOR_QUAD_CurrentVersionRun_282a {
  strings:
    $key_282a = { 7b 45 [2] 5f 4b [2] 74 67 [2] 5a 45 [2] 4e 5e [2] 41 44 [2] 5f 59 [2] 5d 58 [2] 46 5e [2] 5a 59 [2] 46 76 }

  condition:
    any of them
}