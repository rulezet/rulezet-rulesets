rule TTP_XOR_QUAD_CurrentVersionRun_e539 {
  strings:
    $key_e539 = { b6 56 [2] 92 58 [2] b9 74 [2] 97 56 [2] 83 4d [2] 8c 57 [2] 92 4a [2] 90 4b [2] 8b 4d [2] 97 4a [2] 8b 65 }

  condition:
    any of them
}