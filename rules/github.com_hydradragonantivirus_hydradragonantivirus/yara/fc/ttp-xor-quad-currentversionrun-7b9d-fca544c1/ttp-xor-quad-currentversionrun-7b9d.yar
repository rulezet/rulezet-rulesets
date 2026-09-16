rule TTP_XOR_QUAD_CurrentVersionRun_7b9d {
  strings:
    $key_7b9d = { 28 f2 [2] 0c fc [2] 27 d0 [2] 09 f2 [2] 1d e9 [2] 12 f3 [2] 0c ee [2] 0e ef [2] 15 e9 [2] 09 ee [2] 15 c1 }

  condition:
    any of them
}