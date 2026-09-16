rule TTP_XOR_QUAD_CurrentVersionRun_3d2d {
  strings:
    $key_3d2d = { 6e 42 [2] 4a 4c [2] 61 60 [2] 4f 42 [2] 5b 59 [2] 54 43 [2] 4a 5e [2] 48 5f [2] 53 59 [2] 4f 5e [2] 53 71 }

  condition:
    any of them
}