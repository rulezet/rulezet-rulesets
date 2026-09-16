rule TTP_XOR_QUAD_CurrentVersionRun_0f4a {
  strings:
    $key_0f4a = { 5c 25 [2] 78 2b [2] 53 07 [2] 7d 25 [2] 69 3e [2] 66 24 [2] 78 39 [2] 7a 38 [2] 61 3e [2] 7d 39 [2] 61 16 }

  condition:
    any of them
}