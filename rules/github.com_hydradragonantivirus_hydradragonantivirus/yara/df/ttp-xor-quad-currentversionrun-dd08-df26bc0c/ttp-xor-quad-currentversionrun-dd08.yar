rule TTP_XOR_QUAD_CurrentVersionRun_dd08 {
  strings:
    $key_dd08 = { 8e 67 [2] aa 69 [2] 81 45 [2] af 67 [2] bb 7c [2] b4 66 [2] aa 7b [2] a8 7a [2] b3 7c [2] af 7b [2] b3 54 }

  condition:
    any of them
}