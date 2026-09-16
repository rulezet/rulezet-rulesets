rule TTP_XOR_QUAD_CurrentVersionRun_e53b {
  strings:
    $key_e53b = { b6 54 [2] 92 5a [2] b9 76 [2] 97 54 [2] 83 4f [2] 8c 55 [2] 92 48 [2] 90 49 [2] 8b 4f [2] 97 48 [2] 8b 67 }

  condition:
    any of them
}