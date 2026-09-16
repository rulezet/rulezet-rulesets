rule TTP_XOR_QUAD_CurrentVersionRun_563b {
  strings:
    $key_563b = { 05 54 [2] 21 5a [2] 0a 76 [2] 24 54 [2] 30 4f [2] 3f 55 [2] 21 48 [2] 23 49 [2] 38 4f [2] 24 48 [2] 38 67 }

  condition:
    any of them
}