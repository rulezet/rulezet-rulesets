rule TTP_XOR_QUAD_CurrentVersionRun_ca01 {
  strings:
    $key_ca01 = { 99 6e [2] bd 60 [2] 96 4c [2] b8 6e [2] ac 75 [2] a3 6f [2] bd 72 [2] bf 73 [2] a4 75 [2] b8 72 [2] a4 5d }

  condition:
    any of them
}