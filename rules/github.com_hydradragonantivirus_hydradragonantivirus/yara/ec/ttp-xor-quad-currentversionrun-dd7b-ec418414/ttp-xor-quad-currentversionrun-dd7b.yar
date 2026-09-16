rule TTP_XOR_QUAD_CurrentVersionRun_dd7b {
  strings:
    $key_dd7b = { 8e 14 [2] aa 1a [2] 81 36 [2] af 14 [2] bb 0f [2] b4 15 [2] aa 08 [2] a8 09 [2] b3 0f [2] af 08 [2] b3 27 }

  condition:
    any of them
}