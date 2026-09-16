rule TTP_XOR_QUAD_CurrentVersionRun_653a {
  strings:
    $key_653a = { 36 55 [2] 12 5b [2] 39 77 [2] 17 55 [2] 03 4e [2] 0c 54 [2] 12 49 [2] 10 48 [2] 0b 4e [2] 17 49 [2] 0b 66 }

  condition:
    any of them
}