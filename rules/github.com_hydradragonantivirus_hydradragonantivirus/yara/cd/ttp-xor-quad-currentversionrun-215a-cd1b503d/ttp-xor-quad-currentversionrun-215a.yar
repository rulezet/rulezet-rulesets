rule TTP_XOR_QUAD_CurrentVersionRun_215a {
  strings:
    $key_215a = { 72 35 [2] 56 3b [2] 7d 17 [2] 53 35 [2] 47 2e [2] 48 34 [2] 56 29 [2] 54 28 [2] 4f 2e [2] 53 29 [2] 4f 06 }

  condition:
    any of them
}