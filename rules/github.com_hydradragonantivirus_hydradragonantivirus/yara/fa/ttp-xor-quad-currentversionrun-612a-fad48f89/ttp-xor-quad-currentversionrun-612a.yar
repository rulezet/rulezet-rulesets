rule TTP_XOR_QUAD_CurrentVersionRun_612a {
  strings:
    $key_612a = { 32 45 [2] 16 4b [2] 3d 67 [2] 13 45 [2] 07 5e [2] 08 44 [2] 16 59 [2] 14 58 [2] 0f 5e [2] 13 59 [2] 0f 76 }

  condition:
    any of them
}