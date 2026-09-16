rule TTP_XOR_QUAD_CurrentVersionRun_e3e7 {
  strings:
    $key_e3e7 = { b0 88 [2] 94 86 [2] bf aa [2] 91 88 [2] 85 93 [2] 8a 89 [2] 94 94 [2] 96 95 [2] 8d 93 [2] 91 94 [2] 8d bb }

  condition:
    any of them
}