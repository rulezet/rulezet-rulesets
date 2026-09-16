rule TTP_XOR_QUAD_CurrentVersionRun_6e22 {
  strings:
    $key_6e22 = { 3d 4d [2] 19 43 [2] 32 6f [2] 1c 4d [2] 08 56 [2] 07 4c [2] 19 51 [2] 1b 50 [2] 00 56 [2] 1c 51 [2] 00 7e }

  condition:
    any of them
}