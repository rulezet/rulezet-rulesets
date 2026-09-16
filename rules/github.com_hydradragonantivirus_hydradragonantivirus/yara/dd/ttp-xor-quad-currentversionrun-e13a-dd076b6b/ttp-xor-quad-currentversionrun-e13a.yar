rule TTP_XOR_QUAD_CurrentVersionRun_e13a {
  strings:
    $key_e13a = { b2 55 [2] 96 5b [2] bd 77 [2] 93 55 [2] 87 4e [2] 88 54 [2] 96 49 [2] 94 48 [2] 8f 4e [2] 93 49 [2] 8f 66 }

  condition:
    any of them
}