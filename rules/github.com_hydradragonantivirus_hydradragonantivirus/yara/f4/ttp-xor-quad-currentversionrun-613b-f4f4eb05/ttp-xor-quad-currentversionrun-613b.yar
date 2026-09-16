rule TTP_XOR_QUAD_CurrentVersionRun_613b {
  strings:
    $key_613b = { 32 54 [2] 16 5a [2] 3d 76 [2] 13 54 [2] 07 4f [2] 08 55 [2] 16 48 [2] 14 49 [2] 0f 4f [2] 13 48 [2] 0f 67 }

  condition:
    any of them
}