rule TTP_XOR_QUAD_CurrentVersionRun_3d5a {
  strings:
    $key_3d5a = { 6e 35 [2] 4a 3b [2] 61 17 [2] 4f 35 [2] 5b 2e [2] 54 34 [2] 4a 29 [2] 48 28 [2] 53 2e [2] 4f 29 [2] 53 06 }

  condition:
    any of them
}