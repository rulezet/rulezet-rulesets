rule TTP_XOR_QUAD_CurrentVersionRun_3d01 {
  strings:
    $key_3d01 = { 6e 6e [2] 4a 60 [2] 61 4c [2] 4f 6e [2] 5b 75 [2] 54 6f [2] 4a 72 [2] 48 73 [2] 53 75 [2] 4f 72 [2] 53 5d }

  condition:
    any of them
}