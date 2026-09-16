rule TTP_XOR_QUAD_CurrentVersionRun_e0ca {
  strings:
    $key_e0ca = { b3 a5 [2] 97 ab [2] bc 87 [2] 92 a5 [2] 86 be [2] 89 a4 [2] 97 b9 [2] 95 b8 [2] 8e be [2] 92 b9 [2] 8e 96 }

  condition:
    any of them
}