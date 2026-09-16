rule TTP_XOR_QUAD_CurrentVersionRun_d8fa {
  strings:
    $key_d8fa = { 8b 95 [2] af 9b [2] 84 b7 [2] aa 95 [2] be 8e [2] b1 94 [2] af 89 [2] ad 88 [2] b6 8e [2] aa 89 [2] b6 a6 }

  condition:
    any of them
}