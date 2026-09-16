rule TTP_XOR_QUAD_CurrentVersionRun_fc70 {
  strings:
    $key_fc70 = { af 1f [2] 8b 11 [2] a0 3d [2] 8e 1f [2] 9a 04 [2] 95 1e [2] 8b 03 [2] 89 02 [2] 92 04 [2] 8e 03 [2] 92 2c }

  condition:
    any of them
}