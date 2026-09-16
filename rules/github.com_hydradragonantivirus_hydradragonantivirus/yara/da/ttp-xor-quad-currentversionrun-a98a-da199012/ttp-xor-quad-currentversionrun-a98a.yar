rule TTP_XOR_QUAD_CurrentVersionRun_a98a {
  strings:
    $key_a98a = { fa e5 [2] de eb [2] f5 c7 [2] db e5 [2] cf fe [2] c0 e4 [2] de f9 [2] dc f8 [2] c7 fe [2] db f9 [2] c7 d6 }

  condition:
    any of them
}