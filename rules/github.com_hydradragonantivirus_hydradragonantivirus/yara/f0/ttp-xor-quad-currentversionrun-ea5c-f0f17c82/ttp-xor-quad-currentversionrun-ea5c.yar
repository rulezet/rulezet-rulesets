rule TTP_XOR_QUAD_CurrentVersionRun_ea5c {
  strings:
    $key_ea5c = { b9 33 [2] 9d 3d [2] b6 11 [2] 98 33 [2] 8c 28 [2] 83 32 [2] 9d 2f [2] 9f 2e [2] 84 28 [2] 98 2f [2] 84 00 }

  condition:
    any of them
}