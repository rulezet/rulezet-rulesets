rule TTP_XOR_QUAD_CurrentVersionRun_610f {
  strings:
    $key_610f = { 32 60 [2] 16 6e [2] 3d 42 [2] 13 60 [2] 07 7b [2] 08 61 [2] 16 7c [2] 14 7d [2] 0f 7b [2] 13 7c [2] 0f 53 }

  condition:
    any of them
}