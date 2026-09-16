rule TTP_XOR_QUAD_CurrentVersionRun_d818 {
  strings:
    $key_d818 = { 8b 77 [2] af 79 [2] 84 55 [2] aa 77 [2] be 6c [2] b1 76 [2] af 6b [2] ad 6a [2] b6 6c [2] aa 6b [2] b6 44 }

  condition:
    any of them
}