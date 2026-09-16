rule TTP_XOR_QUAD_CurrentVersionRun_dd34 {
  strings:
    $key_dd34 = { 8e 5b [2] aa 55 [2] 81 79 [2] af 5b [2] bb 40 [2] b4 5a [2] aa 47 [2] a8 46 [2] b3 40 [2] af 47 [2] b3 68 }

  condition:
    any of them
}