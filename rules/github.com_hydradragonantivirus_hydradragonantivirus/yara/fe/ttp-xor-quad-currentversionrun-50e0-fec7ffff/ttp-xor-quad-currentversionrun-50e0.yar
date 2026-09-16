rule TTP_XOR_QUAD_CurrentVersionRun_50e0 {
  strings:
    $key_50e0 = { 03 8f [2] 27 81 [2] 0c ad [2] 22 8f [2] 36 94 [2] 39 8e [2] 27 93 [2] 25 92 [2] 3e 94 [2] 22 93 [2] 3e bc }

  condition:
    any of them
}