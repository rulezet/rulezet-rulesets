rule TTP_XOR_QUAD_CurrentVersionRun_e0f6 {
  strings:
    $key_e0f6 = { b3 99 [2] 97 97 [2] bc bb [2] 92 99 [2] 86 82 [2] 89 98 [2] 97 85 [2] 95 84 [2] 8e 82 [2] 92 85 [2] 8e aa }

  condition:
    any of them
}