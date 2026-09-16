rule TTP_XOR_QUAD_CurrentVersionRun_483a {
  strings:
    $key_483a = { 1b 55 [2] 3f 5b [2] 14 77 [2] 3a 55 [2] 2e 4e [2] 21 54 [2] 3f 49 [2] 3d 48 [2] 26 4e [2] 3a 49 [2] 26 66 }

  condition:
    any of them
}