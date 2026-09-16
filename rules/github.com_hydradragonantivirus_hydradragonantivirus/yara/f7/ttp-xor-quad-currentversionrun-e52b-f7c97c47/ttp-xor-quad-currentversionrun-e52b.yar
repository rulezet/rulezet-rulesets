rule TTP_XOR_QUAD_CurrentVersionRun_e52b {
  strings:
    $key_e52b = { b6 44 [2] 92 4a [2] b9 66 [2] 97 44 [2] 83 5f [2] 8c 45 [2] 92 58 [2] 90 59 [2] 8b 5f [2] 97 58 [2] 8b 77 }

  condition:
    any of them
}