rule TTP_XOR_QUAD_CurrentVersionRun_b260 {
  strings:
    $key_b260 = { e1 0f [2] c5 01 [2] ee 2d [2] c0 0f [2] d4 14 [2] db 0e [2] c5 13 [2] c7 12 [2] dc 14 [2] c0 13 [2] dc 3c }

  condition:
    any of them
}