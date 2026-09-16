rule TTP_XOR_QUAD_CurrentVersionRun_b202 {
  strings:
    $key_b202 = { e1 6d [2] c5 63 [2] ee 4f [2] c0 6d [2] d4 76 [2] db 6c [2] c5 71 [2] c7 70 [2] dc 76 [2] c0 71 [2] dc 5e }

  condition:
    any of them
}