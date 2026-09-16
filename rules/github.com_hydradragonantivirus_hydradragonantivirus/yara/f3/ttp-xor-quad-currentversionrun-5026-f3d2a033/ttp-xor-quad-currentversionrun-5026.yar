rule TTP_XOR_QUAD_CurrentVersionRun_5026 {
  strings:
    $key_5026 = { 03 49 [2] 27 47 [2] 0c 6b [2] 22 49 [2] 36 52 [2] 39 48 [2] 27 55 [2] 25 54 [2] 3e 52 [2] 22 55 [2] 3e 7a }

  condition:
    any of them
}