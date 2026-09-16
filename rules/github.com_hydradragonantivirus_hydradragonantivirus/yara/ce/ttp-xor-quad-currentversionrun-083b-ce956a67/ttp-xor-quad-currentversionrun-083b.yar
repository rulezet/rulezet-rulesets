rule TTP_XOR_QUAD_CurrentVersionRun_083b {
  strings:
    $key_083b = { 5b 54 [2] 7f 5a [2] 54 76 [2] 7a 54 [2] 6e 4f [2] 61 55 [2] 7f 48 [2] 7d 49 [2] 66 4f [2] 7a 48 [2] 66 67 }

  condition:
    any of them
}