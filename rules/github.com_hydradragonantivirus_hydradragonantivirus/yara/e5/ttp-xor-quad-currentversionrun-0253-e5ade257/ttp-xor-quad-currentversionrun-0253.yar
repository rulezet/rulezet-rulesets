rule TTP_XOR_QUAD_CurrentVersionRun_0253 {
  strings:
    $key_0253 = { 51 3c [2] 75 32 [2] 5e 1e [2] 70 3c [2] 64 27 [2] 6b 3d [2] 75 20 [2] 77 21 [2] 6c 27 [2] 70 20 [2] 6c 0f }

  condition:
    any of them
}