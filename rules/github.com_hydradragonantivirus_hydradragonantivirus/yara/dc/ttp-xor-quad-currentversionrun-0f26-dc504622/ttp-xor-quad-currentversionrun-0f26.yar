rule TTP_XOR_QUAD_CurrentVersionRun_0f26 {
  strings:
    $key_0f26 = { 5c 49 [2] 78 47 [2] 53 6b [2] 7d 49 [2] 69 52 [2] 66 48 [2] 78 55 [2] 7a 54 [2] 61 52 [2] 7d 55 [2] 61 7a }

  condition:
    any of them
}