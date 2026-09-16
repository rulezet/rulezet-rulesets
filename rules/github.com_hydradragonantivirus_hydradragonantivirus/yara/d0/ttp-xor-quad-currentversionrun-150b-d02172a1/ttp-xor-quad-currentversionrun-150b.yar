rule TTP_XOR_QUAD_CurrentVersionRun_150b {
  strings:
    $key_150b = { 46 64 [2] 62 6a [2] 49 46 [2] 67 64 [2] 73 7f [2] 7c 65 [2] 62 78 [2] 60 79 [2] 7b 7f [2] 67 78 [2] 7b 57 }

  condition:
    any of them
}