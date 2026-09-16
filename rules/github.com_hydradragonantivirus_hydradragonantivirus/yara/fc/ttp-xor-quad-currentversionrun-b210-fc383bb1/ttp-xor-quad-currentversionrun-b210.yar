rule TTP_XOR_QUAD_CurrentVersionRun_b210 {
  strings:
    $key_b210 = { e1 7f [2] c5 71 [2] ee 5d [2] c0 7f [2] d4 64 [2] db 7e [2] c5 63 [2] c7 62 [2] dc 64 [2] c0 63 [2] dc 4c }

  condition:
    any of them
}