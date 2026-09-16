rule TTP_XOR_QUAD_CurrentVersionRun_611e {
  strings:
    $key_611e = { 32 71 [2] 16 7f [2] 3d 53 [2] 13 71 [2] 07 6a [2] 08 70 [2] 16 6d [2] 14 6c [2] 0f 6a [2] 13 6d [2] 0f 42 }

  condition:
    any of them
}