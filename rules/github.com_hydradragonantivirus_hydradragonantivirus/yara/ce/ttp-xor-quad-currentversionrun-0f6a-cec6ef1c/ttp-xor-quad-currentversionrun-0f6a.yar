rule TTP_XOR_QUAD_CurrentVersionRun_0f6a {
  strings:
    $key_0f6a = { 5c 05 [2] 78 0b [2] 53 27 [2] 7d 05 [2] 69 1e [2] 66 04 [2] 78 19 [2] 7a 18 [2] 61 1e [2] 7d 19 [2] 61 36 }

  condition:
    any of them
}