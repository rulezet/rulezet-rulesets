rule TTP_XOR_QUAD_CurrentVersionRun_20e0 {
  strings:
    $key_20e0 = { 73 8f [2] 57 81 [2] 7c ad [2] 52 8f [2] 46 94 [2] 49 8e [2] 57 93 [2] 55 92 [2] 4e 94 [2] 52 93 [2] 4e bc }

  condition:
    any of them
}