rule TTP_XOR_QUAD_CurrentVersionRun_3dea {
  strings:
    $key_3dea = { 6e 85 [2] 4a 8b [2] 61 a7 [2] 4f 85 [2] 5b 9e [2] 54 84 [2] 4a 99 [2] 48 98 [2] 53 9e [2] 4f 99 [2] 53 b6 }

  condition:
    any of them
}