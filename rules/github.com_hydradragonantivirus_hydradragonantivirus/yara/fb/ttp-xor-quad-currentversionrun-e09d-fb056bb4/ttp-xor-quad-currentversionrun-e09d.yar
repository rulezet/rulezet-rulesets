rule TTP_XOR_QUAD_CurrentVersionRun_e09d {
  strings:
    $key_e09d = { b3 f2 [2] 97 fc [2] bc d0 [2] 92 f2 [2] 86 e9 [2] 89 f3 [2] 97 ee [2] 95 ef [2] 8e e9 [2] 92 ee [2] 8e c1 }

  condition:
    any of them
}