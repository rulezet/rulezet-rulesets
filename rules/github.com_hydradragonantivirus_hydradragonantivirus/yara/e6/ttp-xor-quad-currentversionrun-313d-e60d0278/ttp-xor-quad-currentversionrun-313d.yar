rule TTP_XOR_QUAD_CurrentVersionRun_313d {
  strings:
    $key_313d = { 62 52 [2] 46 5c [2] 6d 70 [2] 43 52 [2] 57 49 [2] 58 53 [2] 46 4e [2] 44 4f [2] 5f 49 [2] 43 4e [2] 5f 61 }

  condition:
    any of them
}