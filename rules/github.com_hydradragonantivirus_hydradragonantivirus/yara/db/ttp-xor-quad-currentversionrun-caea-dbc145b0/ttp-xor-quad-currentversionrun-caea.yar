rule TTP_XOR_QUAD_CurrentVersionRun_caea {
  strings:
    $key_caea = { 99 85 [2] bd 8b [2] 96 a7 [2] b8 85 [2] ac 9e [2] a3 84 [2] bd 99 [2] bf 98 [2] a4 9e [2] b8 99 [2] a4 b6 }

  condition:
    any of them
}