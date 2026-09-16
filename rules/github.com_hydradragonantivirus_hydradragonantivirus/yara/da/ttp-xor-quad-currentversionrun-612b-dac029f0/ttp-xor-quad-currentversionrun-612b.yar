rule TTP_XOR_QUAD_CurrentVersionRun_612b {
  strings:
    $key_612b = { 32 44 [2] 16 4a [2] 3d 66 [2] 13 44 [2] 07 5f [2] 08 45 [2] 16 58 [2] 14 59 [2] 0f 5f [2] 13 58 [2] 0f 77 }

  condition:
    any of them
}