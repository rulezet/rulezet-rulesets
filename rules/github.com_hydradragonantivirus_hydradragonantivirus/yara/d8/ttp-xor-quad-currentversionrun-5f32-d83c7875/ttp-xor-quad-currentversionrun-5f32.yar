rule TTP_XOR_QUAD_CurrentVersionRun_5f32 {
  strings:
    $key_5f32 = { 0c 5d [2] 28 53 [2] 03 7f [2] 2d 5d [2] 39 46 [2] 36 5c [2] 28 41 [2] 2a 40 [2] 31 46 [2] 2d 41 [2] 31 6e }

  condition:
    any of them
}