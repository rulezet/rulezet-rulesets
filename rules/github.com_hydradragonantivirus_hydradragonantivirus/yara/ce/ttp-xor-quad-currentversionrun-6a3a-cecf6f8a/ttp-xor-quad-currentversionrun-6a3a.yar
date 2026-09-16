rule TTP_XOR_QUAD_CurrentVersionRun_6a3a {
  strings:
    $key_6a3a = { 39 55 [2] 1d 5b [2] 36 77 [2] 18 55 [2] 0c 4e [2] 03 54 [2] 1d 49 [2] 1f 48 [2] 04 4e [2] 18 49 [2] 04 66 }

  condition:
    any of them
}