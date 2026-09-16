rule TTP_XOR_QUAD_CurrentVersionRun_b24f {
  strings:
    $key_b24f = { e1 20 [2] c5 2e [2] ee 02 [2] c0 20 [2] d4 3b [2] db 21 [2] c5 3c [2] c7 3d [2] dc 3b [2] c0 3c [2] dc 13 }

  condition:
    any of them
}