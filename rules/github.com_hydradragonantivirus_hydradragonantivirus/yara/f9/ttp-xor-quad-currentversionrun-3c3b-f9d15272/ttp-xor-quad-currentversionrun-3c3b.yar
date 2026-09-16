rule TTP_XOR_QUAD_CurrentVersionRun_3c3b {
  strings:
    $key_3c3b = { 6f 54 [2] 4b 5a [2] 60 76 [2] 4e 54 [2] 5a 4f [2] 55 55 [2] 4b 48 [2] 49 49 [2] 52 4f [2] 4e 48 [2] 52 67 }

  condition:
    any of them
}