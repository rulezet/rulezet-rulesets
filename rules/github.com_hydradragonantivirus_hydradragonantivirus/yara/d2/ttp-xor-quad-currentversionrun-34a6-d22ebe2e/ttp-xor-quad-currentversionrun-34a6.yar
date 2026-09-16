rule TTP_XOR_QUAD_CurrentVersionRun_34a6 {
  strings:
    $key_34a6 = { 67 c9 [2] 43 c7 [2] 68 eb [2] 46 c9 [2] 52 d2 [2] 5d c8 [2] 43 d5 [2] 41 d4 [2] 5a d2 [2] 46 d5 [2] 5a fa }

  condition:
    any of them
}