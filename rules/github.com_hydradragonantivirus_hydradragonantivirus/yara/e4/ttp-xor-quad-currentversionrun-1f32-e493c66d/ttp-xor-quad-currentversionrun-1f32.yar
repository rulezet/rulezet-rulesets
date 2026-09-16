rule TTP_XOR_QUAD_CurrentVersionRun_1f32 {
  strings:
    $key_1f32 = { 4c 5d [2] 68 53 [2] 43 7f [2] 6d 5d [2] 79 46 [2] 76 5c [2] 68 41 [2] 6a 40 [2] 71 46 [2] 6d 41 [2] 71 6e }

  condition:
    any of them
}