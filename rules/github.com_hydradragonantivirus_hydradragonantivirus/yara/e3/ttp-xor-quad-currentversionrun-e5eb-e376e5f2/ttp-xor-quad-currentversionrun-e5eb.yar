rule TTP_XOR_QUAD_CurrentVersionRun_e5eb {
  strings:
    $key_e5eb = { b6 84 [2] 92 8a [2] b9 a6 [2] 97 84 [2] 83 9f [2] 8c 85 [2] 92 98 [2] 90 99 [2] 8b 9f [2] 97 98 [2] 8b b7 }

  condition:
    any of them
}