rule TTP_XOR_QUAD_CurrentVersionRun_1a3a {
  strings:
    $key_1a3a = { 49 55 [2] 6d 5b [2] 46 77 [2] 68 55 [2] 7c 4e [2] 73 54 [2] 6d 49 [2] 6f 48 [2] 74 4e [2] 68 49 [2] 74 66 }

  condition:
    any of them
}