rule TTP_XOR_QUAD_CurrentVersionRun_e10e {
  strings:
    $key_e10e = { b2 61 [2] 96 6f [2] bd 43 [2] 93 61 [2] 87 7a [2] 88 60 [2] 96 7d [2] 94 7c [2] 8f 7a [2] 93 7d [2] 8f 52 }

  condition:
    any of them
}