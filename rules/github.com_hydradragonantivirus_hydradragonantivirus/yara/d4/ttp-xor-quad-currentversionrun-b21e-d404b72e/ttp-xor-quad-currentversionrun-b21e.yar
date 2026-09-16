rule TTP_XOR_QUAD_CurrentVersionRun_b21e {
  strings:
    $key_b21e = { e1 71 [2] c5 7f [2] ee 53 [2] c0 71 [2] d4 6a [2] db 70 [2] c5 6d [2] c7 6c [2] dc 6a [2] c0 6d [2] dc 42 }

  condition:
    any of them
}