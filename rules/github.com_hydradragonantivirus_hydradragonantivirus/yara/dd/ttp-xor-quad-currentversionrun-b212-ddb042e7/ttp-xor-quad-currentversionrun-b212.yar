rule TTP_XOR_QUAD_CurrentVersionRun_b212 {
  strings:
    $key_b212 = { e1 7d [2] c5 73 [2] ee 5f [2] c0 7d [2] d4 66 [2] db 7c [2] c5 61 [2] c7 60 [2] dc 66 [2] c0 61 [2] dc 4e }

  condition:
    any of them
}