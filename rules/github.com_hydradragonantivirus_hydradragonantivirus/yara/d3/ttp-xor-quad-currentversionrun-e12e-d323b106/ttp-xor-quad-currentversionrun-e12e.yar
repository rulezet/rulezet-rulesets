rule TTP_XOR_QUAD_CurrentVersionRun_e12e {
  strings:
    $key_e12e = { b2 41 [2] 96 4f [2] bd 63 [2] 93 41 [2] 87 5a [2] 88 40 [2] 96 5d [2] 94 5c [2] 8f 5a [2] 93 5d [2] 8f 72 }

  condition:
    any of them
}