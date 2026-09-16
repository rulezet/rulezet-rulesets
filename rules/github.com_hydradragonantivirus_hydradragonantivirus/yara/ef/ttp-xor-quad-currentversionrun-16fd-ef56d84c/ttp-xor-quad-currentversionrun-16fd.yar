rule TTP_XOR_QUAD_CurrentVersionRun_16fd {
  strings:
    $key_16fd = { 45 92 [2] 61 9c [2] 4a b0 [2] 64 92 [2] 70 89 [2] 7f 93 [2] 61 8e [2] 63 8f [2] 78 89 [2] 64 8e [2] 78 a1 }

  condition:
    any of them
}