rule TTP_XOR_QUAD_CurrentVersionRun_caf7 {
  strings:
    $key_caf7 = { 99 98 [2] bd 96 [2] 96 ba [2] b8 98 [2] ac 83 [2] a3 99 [2] bd 84 [2] bf 85 [2] a4 83 [2] b8 84 [2] a4 ab }

  condition:
    any of them
}