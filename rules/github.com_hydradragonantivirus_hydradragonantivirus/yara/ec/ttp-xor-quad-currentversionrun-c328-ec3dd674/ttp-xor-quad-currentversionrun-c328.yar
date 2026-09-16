rule TTP_XOR_QUAD_CurrentVersionRun_c328 {
  strings:
    $key_c328 = { 90 47 [2] b4 49 [2] 9f 65 [2] b1 47 [2] a5 5c [2] aa 46 [2] b4 5b [2] b6 5a [2] ad 5c [2] b1 5b [2] ad 74 }

  condition:
    any of them
}