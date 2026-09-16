rule TTP_XOR_QUAD_CurrentVersionRun_98f6 {
  strings:
    $key_98f6 = { cb 99 [2] ef 97 [2] c4 bb [2] ea 99 [2] fe 82 [2] f1 98 [2] ef 85 [2] ed 84 [2] f6 82 [2] ea 85 [2] f6 aa }

  condition:
    any of them
}