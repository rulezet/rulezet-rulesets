rule TTP_XOR_QUAD_CurrentVersionRun_342c {
  strings:
    $key_342c = { 67 43 [2] 43 4d [2] 68 61 [2] 46 43 [2] 52 58 [2] 5d 42 [2] 43 5f [2] 41 5e [2] 5a 58 [2] 46 5f [2] 5a 70 }

  condition:
    any of them
}