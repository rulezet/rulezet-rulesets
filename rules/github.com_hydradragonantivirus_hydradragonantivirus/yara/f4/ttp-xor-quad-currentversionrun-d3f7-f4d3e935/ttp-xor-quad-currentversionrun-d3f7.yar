rule TTP_XOR_QUAD_CurrentVersionRun_d3f7 {
  strings:
    $key_d3f7 = { 80 98 [2] a4 96 [2] 8f ba [2] a1 98 [2] b5 83 [2] ba 99 [2] a4 84 [2] a6 85 [2] bd 83 [2] a1 84 [2] bd ab }

  condition:
    any of them
}