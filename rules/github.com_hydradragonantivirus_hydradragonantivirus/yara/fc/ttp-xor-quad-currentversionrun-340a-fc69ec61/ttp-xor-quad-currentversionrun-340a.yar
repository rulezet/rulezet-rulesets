rule TTP_XOR_QUAD_CurrentVersionRun_340a {
  strings:
    $key_340a = { 67 65 [2] 43 6b [2] 68 47 [2] 46 65 [2] 52 7e [2] 5d 64 [2] 43 79 [2] 41 78 [2] 5a 7e [2] 46 79 [2] 5a 56 }

  condition:
    any of them
}