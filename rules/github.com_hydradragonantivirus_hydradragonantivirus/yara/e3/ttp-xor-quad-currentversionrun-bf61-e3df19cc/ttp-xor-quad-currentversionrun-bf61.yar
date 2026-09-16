rule TTP_XOR_QUAD_CurrentVersionRun_bf61 {
  strings:
    $key_bf61 = { ec 0e [2] c8 00 [2] e3 2c [2] cd 0e [2] d9 15 [2] d6 0f [2] c8 12 [2] ca 13 [2] d1 15 [2] cd 12 [2] d1 3d }

  condition:
    any of them
}