rule TTP_XOR_QUAD_CurrentVersionRun_a638 {
  strings:
    $key_a638 = { f5 57 [2] d1 59 [2] fa 75 [2] d4 57 [2] c0 4c [2] cf 56 [2] d1 4b [2] d3 4a [2] c8 4c [2] d4 4b [2] c8 64 }

  condition:
    any of them
}