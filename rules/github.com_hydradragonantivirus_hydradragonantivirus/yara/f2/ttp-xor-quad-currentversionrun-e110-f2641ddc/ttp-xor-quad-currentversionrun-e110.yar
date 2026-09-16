rule TTP_XOR_QUAD_CurrentVersionRun_e110 {
  strings:
    $key_e110 = { b2 7f [2] 96 71 [2] bd 5d [2] 93 7f [2] 87 64 [2] 88 7e [2] 96 63 [2] 94 62 [2] 8f 64 [2] 93 63 [2] 8f 4c }

  condition:
    any of them
}