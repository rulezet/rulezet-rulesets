rule TTP_XOR_QUAD_CurrentVersionRun_e561 {
  strings:
    $key_e561 = { b6 0e [2] 92 00 [2] b9 2c [2] 97 0e [2] 83 15 [2] 8c 0f [2] 92 12 [2] 90 13 [2] 8b 15 [2] 97 12 [2] 8b 3d }

  condition:
    any of them
}