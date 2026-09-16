rule TTP_XOR_QUAD_CurrentVersionRun_e353 {
  strings:
    $key_e353 = { b0 3c [2] 94 32 [2] bf 1e [2] 91 3c [2] 85 27 [2] 8a 3d [2] 94 20 [2] 96 21 [2] 8d 27 [2] 91 20 [2] 8d 0f }

  condition:
    any of them
}