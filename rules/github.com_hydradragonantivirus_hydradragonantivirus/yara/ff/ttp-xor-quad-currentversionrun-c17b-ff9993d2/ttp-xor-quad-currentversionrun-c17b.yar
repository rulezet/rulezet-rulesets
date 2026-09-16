rule TTP_XOR_QUAD_CurrentVersionRun_c17b {
  strings:
    $key_c17b = { 92 14 [2] b6 1a [2] 9d 36 [2] b3 14 [2] a7 0f [2] a8 15 [2] b6 08 [2] b4 09 [2] af 0f [2] b3 08 [2] af 27 }

  condition:
    any of them
}