rule TTP_XOR_QUAD_CurrentVersionRun_122a {
  strings:
    $key_122a = { 41 45 [2] 65 4b [2] 4e 67 [2] 60 45 [2] 74 5e [2] 7b 44 [2] 65 59 [2] 67 58 [2] 7c 5e [2] 60 59 [2] 7c 76 }

  condition:
    any of them
}