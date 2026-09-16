rule TTP_XOR_QUAD_CurrentVersionRun_b227 {
  strings:
    $key_b227 = { e1 48 [2] c5 46 [2] ee 6a [2] c0 48 [2] d4 53 [2] db 49 [2] c5 54 [2] c7 55 [2] dc 53 [2] c0 54 [2] dc 7b }

  condition:
    any of them
}