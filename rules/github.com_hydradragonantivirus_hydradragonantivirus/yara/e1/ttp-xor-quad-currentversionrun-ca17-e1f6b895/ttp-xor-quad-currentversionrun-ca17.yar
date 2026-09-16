rule TTP_XOR_QUAD_CurrentVersionRun_ca17 {
  strings:
    $key_ca17 = { 99 78 [2] bd 76 [2] 96 5a [2] b8 78 [2] ac 63 [2] a3 79 [2] bd 64 [2] bf 65 [2] a4 63 [2] b8 64 [2] a4 4b }

  condition:
    any of them
}