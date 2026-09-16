rule TTP_XOR_QUAD_CurrentVersionRun_d87e {
  strings:
    $key_d87e = { 8b 11 [2] af 1f [2] 84 33 [2] aa 11 [2] be 0a [2] b1 10 [2] af 0d [2] ad 0c [2] b6 0a [2] aa 0d [2] b6 22 }

  condition:
    any of them
}