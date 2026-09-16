rule TTP_XOR_QUAD_CurrentVersionRun_120b {
  strings:
    $key_120b = { 41 64 [2] 65 6a [2] 4e 46 [2] 60 64 [2] 74 7f [2] 7b 65 [2] 65 78 [2] 67 79 [2] 7c 7f [2] 60 78 [2] 7c 57 }

  condition:
    any of them
}