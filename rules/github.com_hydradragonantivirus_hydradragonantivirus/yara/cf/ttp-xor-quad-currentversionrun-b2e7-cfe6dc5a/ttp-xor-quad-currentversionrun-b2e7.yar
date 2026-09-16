rule TTP_XOR_QUAD_CurrentVersionRun_b2e7 {
  strings:
    $key_b2e7 = { e1 88 [2] c5 86 [2] ee aa [2] c0 88 [2] d4 93 [2] db 89 [2] c5 94 [2] c7 95 [2] dc 93 [2] c0 94 [2] dc bb }

  condition:
    any of them
}