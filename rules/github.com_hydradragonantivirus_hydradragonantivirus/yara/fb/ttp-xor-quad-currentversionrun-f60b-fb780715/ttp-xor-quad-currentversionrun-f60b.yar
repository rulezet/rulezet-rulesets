rule TTP_XOR_QUAD_CurrentVersionRun_f60b {
  strings:
    $key_f60b = { a5 64 [2] 81 6a [2] aa 46 [2] 84 64 [2] 90 7f [2] 9f 65 [2] 81 78 [2] 83 79 [2] 98 7f [2] 84 78 [2] 98 57 }

  condition:
    any of them
}