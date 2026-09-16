rule TTP_XOR_QUAD_CurrentVersionRun_61c5 {
  strings:
    $key_61c5 = { 32 aa [2] 16 a4 [2] 3d 88 [2] 13 aa [2] 07 b1 [2] 08 ab [2] 16 b6 [2] 14 b7 [2] 0f b1 [2] 13 b6 [2] 0f 99 }

  condition:
    any of them
}