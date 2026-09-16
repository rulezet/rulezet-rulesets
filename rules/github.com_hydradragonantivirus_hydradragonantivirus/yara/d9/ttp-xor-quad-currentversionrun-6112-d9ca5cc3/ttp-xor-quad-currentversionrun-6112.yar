rule TTP_XOR_QUAD_CurrentVersionRun_6112 {
  strings:
    $key_6112 = { 32 7d [2] 16 73 [2] 3d 5f [2] 13 7d [2] 07 66 [2] 08 7c [2] 16 61 [2] 14 60 [2] 0f 66 [2] 13 61 [2] 0f 4e }

  condition:
    any of them
}