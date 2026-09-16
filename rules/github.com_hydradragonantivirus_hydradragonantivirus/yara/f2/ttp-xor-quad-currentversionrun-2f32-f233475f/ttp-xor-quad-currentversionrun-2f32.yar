rule TTP_XOR_QUAD_CurrentVersionRun_2f32 {
  strings:
    $key_2f32 = { 7c 5d [2] 58 53 [2] 73 7f [2] 5d 5d [2] 49 46 [2] 46 5c [2] 58 41 [2] 5a 40 [2] 41 46 [2] 5d 41 [2] 41 6e }

  condition:
    any of them
}