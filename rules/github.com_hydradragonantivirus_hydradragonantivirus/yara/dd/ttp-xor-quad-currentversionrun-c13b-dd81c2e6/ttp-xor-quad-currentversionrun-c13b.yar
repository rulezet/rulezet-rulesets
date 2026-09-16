rule TTP_XOR_QUAD_CurrentVersionRun_c13b {
  strings:
    $key_c13b = { 92 54 [2] b6 5a [2] 9d 76 [2] b3 54 [2] a7 4f [2] a8 55 [2] b6 48 [2] b4 49 [2] af 4f [2] b3 48 [2] af 67 }

  condition:
    any of them
}