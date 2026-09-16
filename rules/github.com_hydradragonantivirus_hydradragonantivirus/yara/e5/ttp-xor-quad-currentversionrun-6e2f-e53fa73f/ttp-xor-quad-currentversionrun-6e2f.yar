rule TTP_XOR_QUAD_CurrentVersionRun_6e2f {
  strings:
    $key_6e2f = { 3d 40 [2] 19 4e [2] 32 62 [2] 1c 40 [2] 08 5b [2] 07 41 [2] 19 5c [2] 1b 5d [2] 00 5b [2] 1c 5c [2] 00 73 }

  condition:
    any of them
}