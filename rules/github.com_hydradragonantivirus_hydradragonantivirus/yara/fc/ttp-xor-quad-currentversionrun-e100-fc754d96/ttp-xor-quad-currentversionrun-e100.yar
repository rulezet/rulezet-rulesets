rule TTP_XOR_QUAD_CurrentVersionRun_e100 {
  strings:
    $key_e100 = { b2 6f [2] 96 61 [2] bd 4d [2] 93 6f [2] 87 74 [2] 88 6e [2] 96 73 [2] 94 72 [2] 8f 74 [2] 93 73 [2] 8f 5c }

  condition:
    any of them
}