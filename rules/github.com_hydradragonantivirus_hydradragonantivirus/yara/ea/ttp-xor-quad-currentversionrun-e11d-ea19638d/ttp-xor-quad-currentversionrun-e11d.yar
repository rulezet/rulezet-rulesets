rule TTP_XOR_QUAD_CurrentVersionRun_e11d {
  strings:
    $key_e11d = { b2 72 [2] 96 7c [2] bd 50 [2] 93 72 [2] 87 69 [2] 88 73 [2] 96 6e [2] 94 6f [2] 8f 69 [2] 93 6e [2] 8f 41 }

  condition:
    any of them
}