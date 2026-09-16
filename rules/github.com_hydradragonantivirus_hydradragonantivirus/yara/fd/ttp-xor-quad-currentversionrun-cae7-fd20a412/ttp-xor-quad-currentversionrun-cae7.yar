rule TTP_XOR_QUAD_CurrentVersionRun_cae7 {
  strings:
    $key_cae7 = { 99 88 [2] bd 86 [2] 96 aa [2] b8 88 [2] ac 93 [2] a3 89 [2] bd 94 [2] bf 95 [2] a4 93 [2] b8 94 [2] a4 bb }

  condition:
    any of them
}