rule TTP_XOR_QUAD_CurrentVersionRun_e131 {
  strings:
    $key_e131 = { b2 5e [2] 96 50 [2] bd 7c [2] 93 5e [2] 87 45 [2] 88 5f [2] 96 42 [2] 94 43 [2] 8f 45 [2] 93 42 [2] 8f 6d }

  condition:
    any of them
}