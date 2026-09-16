rule TTP_XOR_QUAD_CurrentVersionRun_3216 {
  strings:
    $key_3216 = { 61 79 [2] 45 77 [2] 6e 5b [2] 40 79 [2] 54 62 [2] 5b 78 [2] 45 65 [2] 47 64 [2] 5c 62 [2] 40 65 [2] 5c 4a }

  condition:
    any of them
}