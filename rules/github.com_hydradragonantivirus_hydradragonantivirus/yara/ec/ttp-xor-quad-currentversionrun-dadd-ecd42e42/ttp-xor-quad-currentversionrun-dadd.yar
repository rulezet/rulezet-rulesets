rule TTP_XOR_QUAD_CurrentVersionRun_dadd {
  strings:
    $key_dadd = { 89 b2 [2] ad bc [2] 86 90 [2] a8 b2 [2] bc a9 [2] b3 b3 [2] ad ae [2] af af [2] b4 a9 [2] a8 ae [2] b4 81 }

  condition:
    any of them
}