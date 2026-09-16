rule TTP_XOR_QUAD_CurrentVersionRun_033b {
  strings:
    $key_033b = { 50 54 [2] 74 5a [2] 5f 76 [2] 71 54 [2] 65 4f [2] 6a 55 [2] 74 48 [2] 76 49 [2] 6d 4f [2] 71 48 [2] 6d 67 }

  condition:
    any of them
}