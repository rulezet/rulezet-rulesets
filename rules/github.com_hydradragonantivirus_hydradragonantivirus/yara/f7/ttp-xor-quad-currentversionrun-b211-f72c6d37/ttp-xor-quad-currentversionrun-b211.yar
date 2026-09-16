rule TTP_XOR_QUAD_CurrentVersionRun_b211 {
  strings:
    $key_b211 = { e1 7e [2] c5 70 [2] ee 5c [2] c0 7e [2] d4 65 [2] db 7f [2] c5 62 [2] c7 63 [2] dc 65 [2] c0 62 [2] dc 4d }

  condition:
    any of them
}