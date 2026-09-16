rule TTP_XOR_QUAD_CurrentVersionRun_b262 {
  strings:
    $key_b262 = { e1 0d [2] c5 03 [2] ee 2f [2] c0 0d [2] d4 16 [2] db 0c [2] c5 11 [2] c7 10 [2] dc 16 [2] c0 11 [2] dc 3e }

  condition:
    any of them
}