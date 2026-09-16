rule TTP_XOR_QUAD_CurrentVersionRun_6afd {
  strings:
    $key_6afd = { 39 92 [2] 1d 9c [2] 36 b0 [2] 18 92 [2] 0c 89 [2] 03 93 [2] 1d 8e [2] 1f 8f [2] 04 89 [2] 18 8e [2] 04 a1 }

  condition:
    any of them
}