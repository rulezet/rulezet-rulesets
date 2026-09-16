rule TTP_XOR_QUAD_CurrentVersionRun_e061 {
  strings:
    $key_e061 = { b3 0e [2] 97 00 [2] bc 2c [2] 92 0e [2] 86 15 [2] 89 0f [2] 97 12 [2] 95 13 [2] 8e 15 [2] 92 12 [2] 8e 3d }

  condition:
    any of them
}