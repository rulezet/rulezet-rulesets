rule TTP_XOR_QUAD_CurrentVersionRun_b21d {
  strings:
    $key_b21d = { e1 72 [2] c5 7c [2] ee 50 [2] c0 72 [2] d4 69 [2] db 73 [2] c5 6e [2] c7 6f [2] dc 69 [2] c0 6e [2] dc 41 }

  condition:
    any of them
}