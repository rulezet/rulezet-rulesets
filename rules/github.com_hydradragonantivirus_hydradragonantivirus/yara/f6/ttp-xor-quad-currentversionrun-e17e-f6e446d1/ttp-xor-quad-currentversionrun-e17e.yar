rule TTP_XOR_QUAD_CurrentVersionRun_e17e {
  strings:
    $key_e17e = { b2 11 [2] 96 1f [2] bd 33 [2] 93 11 [2] 87 0a [2] 88 10 [2] 96 0d [2] 94 0c [2] 8f 0a [2] 93 0d [2] 8f 22 }

  condition:
    any of them
}