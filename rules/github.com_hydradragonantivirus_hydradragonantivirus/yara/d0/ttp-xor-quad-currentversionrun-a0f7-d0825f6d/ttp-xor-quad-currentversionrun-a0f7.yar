rule TTP_XOR_QUAD_CurrentVersionRun_a0f7 {
  strings:
    $key_a0f7 = { f3 98 [2] d7 96 [2] fc ba [2] d2 98 [2] c6 83 [2] c9 99 [2] d7 84 [2] d5 85 [2] ce 83 [2] d2 84 [2] ce ab }

  condition:
    any of them
}