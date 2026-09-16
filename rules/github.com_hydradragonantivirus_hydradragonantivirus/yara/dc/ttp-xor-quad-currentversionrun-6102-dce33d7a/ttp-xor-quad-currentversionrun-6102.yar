rule TTP_XOR_QUAD_CurrentVersionRun_6102 {
  strings:
    $key_6102 = { 32 6d [2] 16 63 [2] 3d 4f [2] 13 6d [2] 07 76 [2] 08 6c [2] 16 71 [2] 14 70 [2] 0f 76 [2] 13 71 [2] 0f 5e }

  condition:
    any of them
}