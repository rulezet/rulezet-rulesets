rule TTP_XOR_QUAD_CurrentVersionRun_fc52 {
  strings:
    $key_fc52 = { af 3d [2] 8b 33 [2] a0 1f [2] 8e 3d [2] 9a 26 [2] 95 3c [2] 8b 21 [2] 89 20 [2] 92 26 [2] 8e 21 [2] 92 0e }

  condition:
    any of them
}