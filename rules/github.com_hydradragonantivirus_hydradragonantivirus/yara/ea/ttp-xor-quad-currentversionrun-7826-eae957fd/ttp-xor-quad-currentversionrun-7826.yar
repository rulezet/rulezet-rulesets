rule TTP_XOR_QUAD_CurrentVersionRun_7826 {
  strings:
    $key_7826 = { 2b 49 [2] 0f 47 [2] 24 6b [2] 0a 49 [2] 1e 52 [2] 11 48 [2] 0f 55 [2] 0d 54 [2] 16 52 [2] 0a 55 [2] 16 7a }

  condition:
    any of them
}