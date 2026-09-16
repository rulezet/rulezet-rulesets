rule TTP_XOR_QUAD_CurrentVersionRun_213a {
  strings:
    $key_213a = { 72 55 [2] 56 5b [2] 7d 77 [2] 53 55 [2] 47 4e [2] 48 54 [2] 56 49 [2] 54 48 [2] 4f 4e [2] 53 49 [2] 4f 66 }

  condition:
    any of them
}