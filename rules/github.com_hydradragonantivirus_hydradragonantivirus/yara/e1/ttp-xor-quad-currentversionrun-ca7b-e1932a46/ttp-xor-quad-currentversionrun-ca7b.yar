rule TTP_XOR_QUAD_CurrentVersionRun_ca7b {
  strings:
    $key_ca7b = { 99 14 [2] bd 1a [2] 96 36 [2] b8 14 [2] ac 0f [2] a3 15 [2] bd 08 [2] bf 09 [2] a4 0f [2] b8 08 [2] a4 27 }

  condition:
    any of them
}