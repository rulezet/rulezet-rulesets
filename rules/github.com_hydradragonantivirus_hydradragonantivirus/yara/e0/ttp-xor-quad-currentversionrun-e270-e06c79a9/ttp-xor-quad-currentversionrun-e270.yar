rule TTP_XOR_QUAD_CurrentVersionRun_e270 {
  strings:
    $key_e270 = { b1 1f [2] 95 11 [2] be 3d [2] 90 1f [2] 84 04 [2] 8b 1e [2] 95 03 [2] 97 02 [2] 8c 04 [2] 90 03 [2] 8c 2c }

  condition:
    any of them
}