rule TTP_XOR_QUAD_CurrentVersionRun_ca7c {
  strings:
    $key_ca7c = { 99 13 [2] bd 1d [2] 96 31 [2] b8 13 [2] ac 08 [2] a3 12 [2] bd 0f [2] bf 0e [2] a4 08 [2] b8 0f [2] a4 20 }

  condition:
    any of them
}