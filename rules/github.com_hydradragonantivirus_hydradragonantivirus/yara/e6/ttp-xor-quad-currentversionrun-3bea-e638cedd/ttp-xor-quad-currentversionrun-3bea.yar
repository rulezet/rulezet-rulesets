rule TTP_XOR_QUAD_CurrentVersionRun_3bea {
  strings:
    $key_3bea = { 68 85 [2] 4c 8b [2] 67 a7 [2] 49 85 [2] 5d 9e [2] 52 84 [2] 4c 99 [2] 4e 98 [2] 55 9e [2] 49 99 [2] 55 b6 }

  condition:
    any of them
}