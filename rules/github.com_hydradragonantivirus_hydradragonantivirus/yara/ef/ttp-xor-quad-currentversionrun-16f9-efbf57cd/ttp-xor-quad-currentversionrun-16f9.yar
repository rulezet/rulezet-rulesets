rule TTP_XOR_QUAD_CurrentVersionRun_16f9 {
  strings:
    $key_16f9 = { 45 96 [2] 61 98 [2] 4a b4 [2] 64 96 [2] 70 8d [2] 7f 97 [2] 61 8a [2] 63 8b [2] 78 8d [2] 64 8a [2] 78 a5 }

  condition:
    any of them
}