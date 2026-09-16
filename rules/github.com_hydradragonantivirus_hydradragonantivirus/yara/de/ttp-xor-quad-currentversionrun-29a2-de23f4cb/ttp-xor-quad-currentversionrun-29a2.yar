rule TTP_XOR_QUAD_CurrentVersionRun_29a2 {
  strings:
    $key_29a2 = { 7a cd [2] 5e c3 [2] 75 ef [2] 5b cd [2] 4f d6 [2] 40 cc [2] 5e d1 [2] 5c d0 [2] 47 d6 [2] 5b d1 [2] 47 fe }

  condition:
    any of them
}