rule TTP_XOR_QUAD_CurrentVersionRun_c43b {
  strings:
    $key_c43b = { 97 54 [2] b3 5a [2] 98 76 [2] b6 54 [2] a2 4f [2] ad 55 [2] b3 48 [2] b1 49 [2] aa 4f [2] b6 48 [2] aa 67 }

  condition:
    any of them
}