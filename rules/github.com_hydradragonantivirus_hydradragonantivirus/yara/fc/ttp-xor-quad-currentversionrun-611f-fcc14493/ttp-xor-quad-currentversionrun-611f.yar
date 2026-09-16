rule TTP_XOR_QUAD_CurrentVersionRun_611f {
  strings:
    $key_611f = { 32 70 [2] 16 7e [2] 3d 52 [2] 13 70 [2] 07 6b [2] 08 71 [2] 16 6c [2] 14 6d [2] 0f 6b [2] 13 6c [2] 0f 43 }

  condition:
    any of them
}