rule TTP_XOR_QUAD_CurrentVersionRun_ccea {
  strings:
    $key_ccea = { 9f 85 [2] bb 8b [2] 90 a7 [2] be 85 [2] aa 9e [2] a5 84 [2] bb 99 [2] b9 98 [2] a2 9e [2] be 99 [2] a2 b6 }

  condition:
    any of them
}