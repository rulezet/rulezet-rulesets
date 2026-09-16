rule TTP_XOR_QUAD_CurrentVersionRun_e00d {
  strings:
    $key_e00d = { b3 62 [2] 97 6c [2] bc 40 [2] 92 62 [2] 86 79 [2] 89 63 [2] 97 7e [2] 95 7f [2] 8e 79 [2] 92 7e [2] 8e 51 }

  condition:
    any of them
}