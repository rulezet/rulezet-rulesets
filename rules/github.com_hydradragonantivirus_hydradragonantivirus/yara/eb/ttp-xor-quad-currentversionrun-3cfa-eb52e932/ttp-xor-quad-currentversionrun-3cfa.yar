rule TTP_XOR_QUAD_CurrentVersionRun_3cfa {
  strings:
    $key_3cfa = { 6f 95 [2] 4b 9b [2] 60 b7 [2] 4e 95 [2] 5a 8e [2] 55 94 [2] 4b 89 [2] 49 88 [2] 52 8e [2] 4e 89 [2] 52 a6 }

  condition:
    any of them
}