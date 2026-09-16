rule TTP_XOR_QUAD_CurrentVersionRun_241a {
  strings:
    $key_241a = { 77 75 [2] 53 7b [2] 78 57 [2] 56 75 [2] 42 6e [2] 4d 74 [2] 53 69 [2] 51 68 [2] 4a 6e [2] 56 69 [2] 4a 46 }

  condition:
    any of them
}