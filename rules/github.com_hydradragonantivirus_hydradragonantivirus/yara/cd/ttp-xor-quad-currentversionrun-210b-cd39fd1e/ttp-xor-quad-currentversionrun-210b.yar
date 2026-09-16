rule TTP_XOR_QUAD_CurrentVersionRun_210b {
  strings:
    $key_210b = { 72 64 [2] 56 6a [2] 7d 46 [2] 53 64 [2] 47 7f [2] 48 65 [2] 56 78 [2] 54 79 [2] 4f 7f [2] 53 78 [2] 4f 57 }

  condition:
    any of them
}