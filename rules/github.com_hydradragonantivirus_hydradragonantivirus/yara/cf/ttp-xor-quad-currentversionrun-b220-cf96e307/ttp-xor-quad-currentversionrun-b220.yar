rule TTP_XOR_QUAD_CurrentVersionRun_b220 {
  strings:
    $key_b220 = { e1 4f [2] c5 41 [2] ee 6d [2] c0 4f [2] d4 54 [2] db 4e [2] c5 53 [2] c7 52 [2] dc 54 [2] c0 53 [2] dc 7c }

  condition:
    any of them
}