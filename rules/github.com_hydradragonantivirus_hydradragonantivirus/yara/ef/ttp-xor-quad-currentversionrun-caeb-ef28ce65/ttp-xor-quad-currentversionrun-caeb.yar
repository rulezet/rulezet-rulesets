rule TTP_XOR_QUAD_CurrentVersionRun_caeb {
  strings:
    $key_caeb = { 99 84 [2] bd 8a [2] 96 a6 [2] b8 84 [2] ac 9f [2] a3 85 [2] bd 98 [2] bf 99 [2] a4 9f [2] b8 98 [2] a4 b7 }

  condition:
    any of them
}