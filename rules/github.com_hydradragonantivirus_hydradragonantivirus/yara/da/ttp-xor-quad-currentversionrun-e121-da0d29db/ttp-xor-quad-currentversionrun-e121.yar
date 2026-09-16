rule TTP_XOR_QUAD_CurrentVersionRun_e121 {
  strings:
    $key_e121 = { b2 4e [2] 96 40 [2] bd 6c [2] 93 4e [2] 87 55 [2] 88 4f [2] 96 52 [2] 94 53 [2] 8f 55 [2] 93 52 [2] 8f 7d }

  condition:
    any of them
}