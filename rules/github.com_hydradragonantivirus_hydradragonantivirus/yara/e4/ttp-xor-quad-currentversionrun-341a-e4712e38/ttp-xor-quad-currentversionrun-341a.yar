rule TTP_XOR_QUAD_CurrentVersionRun_341a {
  strings:
    $key_341a = { 67 75 [2] 43 7b [2] 68 57 [2] 46 75 [2] 52 6e [2] 5d 74 [2] 43 69 [2] 41 68 [2] 5a 6e [2] 46 69 [2] 5a 46 }

  condition:
    any of them
}