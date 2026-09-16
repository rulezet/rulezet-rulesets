rule TTP_XOR_QUAD_CurrentVersionRun_6132 {
  strings:
    $key_6132 = { 32 5d [2] 16 53 [2] 3d 7f [2] 13 5d [2] 07 46 [2] 08 5c [2] 16 41 [2] 14 40 [2] 0f 46 [2] 13 41 [2] 0f 6e }

  condition:
    any of them
}