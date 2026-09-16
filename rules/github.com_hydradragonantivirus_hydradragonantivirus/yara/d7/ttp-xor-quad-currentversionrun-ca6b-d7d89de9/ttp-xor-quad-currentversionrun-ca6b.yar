rule TTP_XOR_QUAD_CurrentVersionRun_ca6b {
  strings:
    $key_ca6b = { 99 04 [2] bd 0a [2] 96 26 [2] b8 04 [2] ac 1f [2] a3 05 [2] bd 18 [2] bf 19 [2] a4 1f [2] b8 18 [2] a4 37 }

  condition:
    any of them
}