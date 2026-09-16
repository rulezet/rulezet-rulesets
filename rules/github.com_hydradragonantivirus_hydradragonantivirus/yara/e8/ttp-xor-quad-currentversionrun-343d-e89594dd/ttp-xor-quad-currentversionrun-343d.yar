rule TTP_XOR_QUAD_CurrentVersionRun_343d {
  strings:
    $key_343d = { 67 52 [2] 43 5c [2] 68 70 [2] 46 52 [2] 52 49 [2] 5d 53 [2] 43 4e [2] 41 4f [2] 5a 49 [2] 46 4e [2] 5a 61 }

  condition:
    any of them
}