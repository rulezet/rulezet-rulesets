rule TTP_XOR_QUAD_CurrentVersionRun_614a {
  strings:
    $key_614a = { 32 25 [2] 16 2b [2] 3d 07 [2] 13 25 [2] 07 3e [2] 08 24 [2] 16 39 [2] 14 38 [2] 0f 3e [2] 13 39 [2] 0f 16 }

  condition:
    any of them
}