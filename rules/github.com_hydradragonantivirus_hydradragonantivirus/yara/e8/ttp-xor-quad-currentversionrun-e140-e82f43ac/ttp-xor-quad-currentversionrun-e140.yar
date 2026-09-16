rule TTP_XOR_QUAD_CurrentVersionRun_e140 {
  strings:
    $key_e140 = { b2 2f [2] 96 21 [2] bd 0d [2] 93 2f [2] 87 34 [2] 88 2e [2] 96 33 [2] 94 32 [2] 8f 34 [2] 93 33 [2] 8f 1c }

  condition:
    any of them
}