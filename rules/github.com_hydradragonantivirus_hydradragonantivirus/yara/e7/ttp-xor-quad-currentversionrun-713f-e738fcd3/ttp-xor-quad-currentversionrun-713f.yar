rule TTP_XOR_QUAD_CurrentVersionRun_713f {
  strings:
    $key_713f = { 22 50 [2] 06 5e [2] 2d 72 [2] 03 50 [2] 17 4b [2] 18 51 [2] 06 4c [2] 04 4d [2] 1f 4b [2] 03 4c [2] 1f 63 }

  condition:
    any of them
}