rule TTP_XOR_QUAD_CurrentVersionRun_544a {
  strings:
    $key_544a = { 07 25 [2] 23 2b [2] 08 07 [2] 26 25 [2] 32 3e [2] 3d 24 [2] 23 39 [2] 21 38 [2] 3a 3e [2] 26 39 [2] 3a 16 }

  condition:
    any of them
}