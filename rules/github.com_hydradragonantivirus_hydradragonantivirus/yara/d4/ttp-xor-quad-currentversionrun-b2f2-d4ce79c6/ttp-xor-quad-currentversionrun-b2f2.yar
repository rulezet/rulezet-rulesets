rule TTP_XOR_QUAD_CurrentVersionRun_b2f2 {
  strings:
    $key_b2f2 = { e1 9d [2] c5 93 [2] ee bf [2] c0 9d [2] d4 86 [2] db 9c [2] c5 81 [2] c7 80 [2] dc 86 [2] c0 81 [2] dc ae }

  condition:
    any of them
}