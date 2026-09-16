rule TTP_XOR_QUAD_CurrentVersionRun_e14a {
  strings:
    $key_e14a = { b2 25 [2] 96 2b [2] bd 07 [2] 93 25 [2] 87 3e [2] 88 24 [2] 96 39 [2] 94 38 [2] 8f 3e [2] 93 39 [2] 8f 16 }

  condition:
    any of them
}