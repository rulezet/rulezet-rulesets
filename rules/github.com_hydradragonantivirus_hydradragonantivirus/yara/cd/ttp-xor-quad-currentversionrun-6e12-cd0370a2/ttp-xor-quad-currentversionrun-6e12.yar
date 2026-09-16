rule TTP_XOR_QUAD_CurrentVersionRun_6e12 {
  strings:
    $key_6e12 = { 3d 7d [2] 19 73 [2] 32 5f [2] 1c 7d [2] 08 66 [2] 07 7c [2] 19 61 [2] 1b 60 [2] 00 66 [2] 1c 61 [2] 00 4e }

  condition:
    any of them
}