rule TTP_XOR_QUAD_CurrentVersionRun_3753 {
  strings:
    $key_3753 = { 64 3c [2] 40 32 [2] 6b 1e [2] 45 3c [2] 51 27 [2] 5e 3d [2] 40 20 [2] 42 21 [2] 59 27 [2] 45 20 [2] 59 0f }

  condition:
    any of them
}