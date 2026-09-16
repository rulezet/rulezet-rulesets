rule TTP_XOR_QUAD_CurrentVersionRun_d809 {
  strings:
    $key_d809 = { 8b 66 [2] af 68 [2] 84 44 [2] aa 66 [2] be 7d [2] b1 67 [2] af 7a [2] ad 7b [2] b6 7d [2] aa 7a [2] b6 55 }

  condition:
    any of them
}