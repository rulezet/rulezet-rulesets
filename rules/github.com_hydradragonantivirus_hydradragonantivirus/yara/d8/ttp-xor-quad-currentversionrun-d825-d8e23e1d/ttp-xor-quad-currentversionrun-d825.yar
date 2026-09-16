rule TTP_XOR_QUAD_CurrentVersionRun_d825 {
  strings:
    $key_d825 = { 8b 4a [2] af 44 [2] 84 68 [2] aa 4a [2] be 51 [2] b1 4b [2] af 56 [2] ad 57 [2] b6 51 [2] aa 56 [2] b6 79 }

  condition:
    any of them
}