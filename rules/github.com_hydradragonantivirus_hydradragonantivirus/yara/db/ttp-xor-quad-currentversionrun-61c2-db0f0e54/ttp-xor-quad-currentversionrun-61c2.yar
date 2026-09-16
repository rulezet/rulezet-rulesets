rule TTP_XOR_QUAD_CurrentVersionRun_61c2 {
  strings:
    $key_61c2 = { 32 ad [2] 16 a3 [2] 3d 8f [2] 13 ad [2] 07 b6 [2] 08 ac [2] 16 b1 [2] 14 b0 [2] 0f b6 [2] 13 b1 [2] 0f 9e }

  condition:
    any of them
}