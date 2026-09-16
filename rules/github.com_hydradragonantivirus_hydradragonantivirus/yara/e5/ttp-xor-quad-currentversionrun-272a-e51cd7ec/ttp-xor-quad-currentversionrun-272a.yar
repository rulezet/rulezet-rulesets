rule TTP_XOR_QUAD_CurrentVersionRun_272a {
  strings:
    $key_272a = { 74 45 [2] 50 4b [2] 7b 67 [2] 55 45 [2] 41 5e [2] 4e 44 [2] 50 59 [2] 52 58 [2] 49 5e [2] 55 59 [2] 49 76 }

  condition:
    any of them
}