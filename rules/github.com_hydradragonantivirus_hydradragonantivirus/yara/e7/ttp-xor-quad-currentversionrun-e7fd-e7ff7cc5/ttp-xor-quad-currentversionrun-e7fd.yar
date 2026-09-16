rule TTP_XOR_QUAD_CurrentVersionRun_e7fd {
  strings:
    $key_e7fd = { b4 92 [2] 90 9c [2] bb b0 [2] 95 92 [2] 81 89 [2] 8e 93 [2] 90 8e [2] 92 8f [2] 89 89 [2] 95 8e [2] 89 a1 }

  condition:
    any of them
}