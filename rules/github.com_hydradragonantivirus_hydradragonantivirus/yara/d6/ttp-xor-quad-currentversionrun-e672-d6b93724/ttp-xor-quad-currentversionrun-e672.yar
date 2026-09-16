rule TTP_XOR_QUAD_CurrentVersionRun_e672 {
  strings:
    $key_e672 = { b5 1d [2] 91 13 [2] ba 3f [2] 94 1d [2] 80 06 [2] 8f 1c [2] 91 01 [2] 93 00 [2] 88 06 [2] 94 01 [2] 88 2e }

  condition:
    any of them
}