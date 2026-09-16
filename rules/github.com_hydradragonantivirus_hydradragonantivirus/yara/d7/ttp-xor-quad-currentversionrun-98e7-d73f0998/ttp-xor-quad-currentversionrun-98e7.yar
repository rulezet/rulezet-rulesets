rule TTP_XOR_QUAD_CurrentVersionRun_98e7 {
  strings:
    $key_98e7 = { cb 88 [2] ef 86 [2] c4 aa [2] ea 88 [2] fe 93 [2] f1 89 [2] ef 94 [2] ed 95 [2] f6 93 [2] ea 94 [2] f6 bb }

  condition:
    any of them
}