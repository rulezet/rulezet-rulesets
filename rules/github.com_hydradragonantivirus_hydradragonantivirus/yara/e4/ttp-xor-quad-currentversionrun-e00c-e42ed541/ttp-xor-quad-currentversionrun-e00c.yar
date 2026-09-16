rule TTP_XOR_QUAD_CurrentVersionRun_e00c {
  strings:
    $key_e00c = { b3 63 [2] 97 6d [2] bc 41 [2] 92 63 [2] 86 78 [2] 89 62 [2] 97 7f [2] 95 7e [2] 8e 78 [2] 92 7f [2] 8e 50 }

  condition:
    any of them
}