rule TTP_XOR_QUAD_CurrentVersionRun_c117 {
  strings:
    $key_c117 = { 92 78 [2] b6 76 [2] 9d 5a [2] b3 78 [2] a7 63 [2] a8 79 [2] b6 64 [2] b4 65 [2] af 63 [2] b3 64 [2] af 4b }

  condition:
    any of them
}