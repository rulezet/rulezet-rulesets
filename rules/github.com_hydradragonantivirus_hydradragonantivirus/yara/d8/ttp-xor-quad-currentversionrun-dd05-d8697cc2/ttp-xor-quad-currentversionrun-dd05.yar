rule TTP_XOR_QUAD_CurrentVersionRun_dd05 {
  strings:
    $key_dd05 = { 8e 6a [2] aa 64 [2] 81 48 [2] af 6a [2] bb 71 [2] b4 6b [2] aa 76 [2] a8 77 [2] b3 71 [2] af 76 [2] b3 59 }

  condition:
    any of them
}