rule TTP_XOR_QUAD_CurrentVersionRun_e16d {
  strings:
    $key_e16d = { b2 02 [2] 96 0c [2] bd 20 [2] 93 02 [2] 87 19 [2] 88 03 [2] 96 1e [2] 94 1f [2] 8f 19 [2] 93 1e [2] 8f 31 }

  condition:
    any of them
}