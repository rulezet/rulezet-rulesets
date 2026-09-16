rule TTP_XOR_QUAD_CurrentVersionRun_e029 {
  strings:
    $key_e029 = { b3 46 [2] 97 48 [2] bc 64 [2] 92 46 [2] 86 5d [2] 89 47 [2] 97 5a [2] 95 5b [2] 8e 5d [2] 92 5a [2] 8e 75 }

  condition:
    any of them
}