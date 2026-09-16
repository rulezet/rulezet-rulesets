rule TTP_XOR_QUAD_CurrentVersionRun_d8ea {
  strings:
    $key_d8ea = { 8b 85 [2] af 8b [2] 84 a7 [2] aa 85 [2] be 9e [2] b1 84 [2] af 99 [2] ad 98 [2] b6 9e [2] aa 99 [2] b6 b6 }

  condition:
    any of them
}