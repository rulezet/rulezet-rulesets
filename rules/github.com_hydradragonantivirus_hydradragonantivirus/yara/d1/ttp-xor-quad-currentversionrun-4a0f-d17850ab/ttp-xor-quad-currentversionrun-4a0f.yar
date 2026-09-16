rule TTP_XOR_QUAD_CurrentVersionRun_4a0f {
  strings:
    $key_4a0f = { 19 60 [2] 3d 6e [2] 16 42 [2] 38 60 [2] 2c 7b [2] 23 61 [2] 3d 7c [2] 3f 7d [2] 24 7b [2] 38 7c [2] 24 53 }

  condition:
    any of them
}