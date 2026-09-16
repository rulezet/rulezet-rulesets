rule TTP_XOR_QUAD_CurrentVersionRun_3f3a {
  strings:
    $key_3f3a = { 6c 55 [2] 48 5b [2] 63 77 [2] 4d 55 [2] 59 4e [2] 56 54 [2] 48 49 [2] 4a 48 [2] 51 4e [2] 4d 49 [2] 51 66 }

  condition:
    any of them
}