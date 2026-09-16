rule TTP_XOR_QUAD_CurrentVersionRun_133a {
  strings:
    $key_133a = { 40 55 [2] 64 5b [2] 4f 77 [2] 61 55 [2] 75 4e [2] 7a 54 [2] 64 49 [2] 66 48 [2] 7d 4e [2] 61 49 [2] 7d 66 }

  condition:
    any of them
}