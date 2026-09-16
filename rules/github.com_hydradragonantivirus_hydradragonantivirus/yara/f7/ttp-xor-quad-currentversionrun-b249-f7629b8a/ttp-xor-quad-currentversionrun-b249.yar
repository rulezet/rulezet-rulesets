rule TTP_XOR_QUAD_CurrentVersionRun_b249 {
  strings:
    $key_b249 = { e1 26 [2] c5 28 [2] ee 04 [2] c0 26 [2] d4 3d [2] db 27 [2] c5 3a [2] c7 3b [2] dc 3d [2] c0 3a [2] dc 15 }

  condition:
    any of them
}