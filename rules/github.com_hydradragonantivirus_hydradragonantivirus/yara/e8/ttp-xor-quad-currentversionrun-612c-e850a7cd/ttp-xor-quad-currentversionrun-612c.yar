rule TTP_XOR_QUAD_CurrentVersionRun_612c {
  strings:
    $key_612c = { 32 43 [2] 16 4d [2] 3d 61 [2] 13 43 [2] 07 58 [2] 08 42 [2] 16 5f [2] 14 5e [2] 0f 58 [2] 13 5f [2] 0f 70 }

  condition:
    any of them
}