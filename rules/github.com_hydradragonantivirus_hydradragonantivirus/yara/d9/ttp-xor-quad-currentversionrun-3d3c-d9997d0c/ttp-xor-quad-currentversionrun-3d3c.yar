rule TTP_XOR_QUAD_CurrentVersionRun_3d3c {
  strings:
    $key_3d3c = { 6e 53 [2] 4a 5d [2] 61 71 [2] 4f 53 [2] 5b 48 [2] 54 52 [2] 4a 4f [2] 48 4e [2] 53 48 [2] 4f 4f [2] 53 60 }

  condition:
    any of them
}