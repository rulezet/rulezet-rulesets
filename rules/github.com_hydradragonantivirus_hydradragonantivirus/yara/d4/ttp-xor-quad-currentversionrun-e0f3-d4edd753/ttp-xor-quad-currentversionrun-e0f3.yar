rule TTP_XOR_QUAD_CurrentVersionRun_e0f3 {
  strings:
    $key_e0f3 = { b3 9c [2] 97 92 [2] bc be [2] 92 9c [2] 86 87 [2] 89 9d [2] 97 80 [2] 95 81 [2] 8e 87 [2] 92 80 [2] 8e af }

  condition:
    any of them
}