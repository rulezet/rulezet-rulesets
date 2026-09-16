rule TTP_XOR_QUAD_CurrentVersionRun_d427 {
  strings:
    $key_d427 = { 87 48 [2] a3 46 [2] 88 6a [2] a6 48 [2] b2 53 [2] bd 49 [2] a3 54 [2] a1 55 [2] ba 53 [2] a6 54 [2] ba 7b }

  condition:
    any of them
}