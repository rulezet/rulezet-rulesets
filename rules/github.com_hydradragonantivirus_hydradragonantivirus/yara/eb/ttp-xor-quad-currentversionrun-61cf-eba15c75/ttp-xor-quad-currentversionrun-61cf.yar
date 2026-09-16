rule TTP_XOR_QUAD_CurrentVersionRun_61cf {
  strings:
    $key_61cf = { 32 a0 [2] 16 ae [2] 3d 82 [2] 13 a0 [2] 07 bb [2] 08 a1 [2] 16 bc [2] 14 bd [2] 0f bb [2] 13 bc [2] 0f 93 }

  condition:
    any of them
}