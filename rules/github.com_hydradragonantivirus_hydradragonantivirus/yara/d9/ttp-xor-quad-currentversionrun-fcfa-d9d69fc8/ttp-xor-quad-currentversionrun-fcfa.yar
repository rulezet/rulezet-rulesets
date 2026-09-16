rule TTP_XOR_QUAD_CurrentVersionRun_fcfa {
  strings:
    $key_fcfa = { af 95 [2] 8b 9b [2] a0 b7 [2] 8e 95 [2] 9a 8e [2] 95 94 [2] 8b 89 [2] 89 88 [2] 92 8e [2] 8e 89 [2] 92 a6 }

  condition:
    any of them
}