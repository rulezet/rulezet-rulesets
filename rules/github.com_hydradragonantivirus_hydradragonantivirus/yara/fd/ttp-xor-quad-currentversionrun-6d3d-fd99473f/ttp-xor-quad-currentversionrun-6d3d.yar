rule TTP_XOR_QUAD_CurrentVersionRun_6d3d {
  strings:
    $key_6d3d = { 3e 52 [2] 1a 5c [2] 31 70 [2] 1f 52 [2] 0b 49 [2] 04 53 [2] 1a 4e [2] 18 4f [2] 03 49 [2] 1f 4e [2] 03 61 }

  condition:
    any of them
}