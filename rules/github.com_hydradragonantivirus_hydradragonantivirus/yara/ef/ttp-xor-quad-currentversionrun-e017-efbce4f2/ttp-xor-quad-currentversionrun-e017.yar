rule TTP_XOR_QUAD_CurrentVersionRun_e017 {
  strings:
    $key_e017 = { b3 78 [2] 97 76 [2] bc 5a [2] 92 78 [2] 86 63 [2] 89 79 [2] 97 64 [2] 95 65 [2] 8e 63 [2] 92 64 [2] 8e 4b }

  condition:
    any of them
}