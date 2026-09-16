rule TTP_XOR_QUAD_CurrentVersionRun_541c {
  strings:
    $key_541c = { 07 73 [2] 23 7d [2] 08 51 [2] 26 73 [2] 32 68 [2] 3d 72 [2] 23 6f [2] 21 6e [2] 3a 68 [2] 26 6f [2] 3a 40 }

  condition:
    any of them
}