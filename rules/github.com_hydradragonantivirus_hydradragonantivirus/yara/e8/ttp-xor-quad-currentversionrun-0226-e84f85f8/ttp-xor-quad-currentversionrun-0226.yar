rule TTP_XOR_QUAD_CurrentVersionRun_0226 {
  strings:
    $key_0226 = { 51 49 [2] 75 47 [2] 5e 6b [2] 70 49 [2] 64 52 [2] 6b 48 [2] 75 55 [2] 77 54 [2] 6c 52 [2] 70 55 [2] 6c 7a }

  condition:
    any of them
}