rule TTP_XOR_QUAD_CurrentVersionRun_cff6 {
  strings:
    $key_cff6 = { 9c 99 [2] b8 97 [2] 93 bb [2] bd 99 [2] a9 82 [2] a6 98 [2] b8 85 [2] ba 84 [2] a1 82 [2] bd 85 [2] a1 aa }

  condition:
    any of them
}