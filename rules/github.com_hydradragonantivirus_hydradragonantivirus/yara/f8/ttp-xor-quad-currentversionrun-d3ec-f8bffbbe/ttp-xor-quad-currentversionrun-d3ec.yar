rule TTP_XOR_QUAD_CurrentVersionRun_d3ec {
  strings:
    $key_d3ec = { 80 83 [2] a4 8d [2] 8f a1 [2] a1 83 [2] b5 98 [2] ba 82 [2] a4 9f [2] a6 9e [2] bd 98 [2] a1 9f [2] bd b0 }

  condition:
    any of them
}