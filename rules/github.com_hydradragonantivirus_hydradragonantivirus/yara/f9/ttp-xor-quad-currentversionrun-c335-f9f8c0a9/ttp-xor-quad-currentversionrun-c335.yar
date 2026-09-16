rule TTP_XOR_QUAD_CurrentVersionRun_c335 {
  strings:
    $key_c335 = { 90 5a [2] b4 54 [2] 9f 78 [2] b1 5a [2] a5 41 [2] aa 5b [2] b4 46 [2] b6 47 [2] ad 41 [2] b1 46 [2] ad 69 }

  condition:
    any of them
}