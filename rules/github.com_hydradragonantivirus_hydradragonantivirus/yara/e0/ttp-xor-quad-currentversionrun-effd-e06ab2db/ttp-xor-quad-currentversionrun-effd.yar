rule TTP_XOR_QUAD_CurrentVersionRun_effd {
  strings:
    $key_effd = { bc 92 [2] 98 9c [2] b3 b0 [2] 9d 92 [2] 89 89 [2] 86 93 [2] 98 8e [2] 9a 8f [2] 81 89 [2] 9d 8e [2] 81 a1 }

  condition:
    any of them
}