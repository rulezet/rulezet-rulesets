rule TTP_XOR_QUAD_CurrentVersionRun_3026 {
  strings:
    $key_3026 = { 63 49 [2] 47 47 [2] 6c 6b [2] 42 49 [2] 56 52 [2] 59 48 [2] 47 55 [2] 45 54 [2] 5e 52 [2] 42 55 [2] 5e 7a }

  condition:
    any of them
}