rule TTP_XOR_QUAD_CurrentVersionRun_d3f8 {
  strings:
    $key_d3f8 = { 80 97 [2] a4 99 [2] 8f b5 [2] a1 97 [2] b5 8c [2] ba 96 [2] a4 8b [2] a6 8a [2] bd 8c [2] a1 8b [2] bd a4 }

  condition:
    any of them
}