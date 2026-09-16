rule TTP_XOR_QUAD_CurrentVersionRun_300b {
  strings:
    $key_300b = { 63 64 [2] 47 6a [2] 6c 46 [2] 42 64 [2] 56 7f [2] 59 65 [2] 47 78 [2] 45 79 [2] 5e 7f [2] 42 78 [2] 5e 57 }

  condition:
    any of them
}