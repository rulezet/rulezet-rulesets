rule TTP_XOR_QUAD_CurrentVersionRun_c10b {
  strings:
    $key_c10b = { 92 64 [2] b6 6a [2] 9d 46 [2] b3 64 [2] a7 7f [2] a8 65 [2] b6 78 [2] b4 79 [2] af 7f [2] b3 78 [2] af 57 }

  condition:
    any of them
}