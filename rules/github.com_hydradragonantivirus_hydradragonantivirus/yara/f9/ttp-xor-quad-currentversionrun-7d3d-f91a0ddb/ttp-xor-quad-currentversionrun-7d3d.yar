rule TTP_XOR_QUAD_CurrentVersionRun_7d3d {
  strings:
    $key_7d3d = { 2e 52 [2] 0a 5c [2] 21 70 [2] 0f 52 [2] 1b 49 [2] 14 53 [2] 0a 4e [2] 08 4f [2] 13 49 [2] 0f 4e [2] 13 61 }

  condition:
    any of them
}