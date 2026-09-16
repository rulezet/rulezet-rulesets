rule TTP_XOR_QUAD_CurrentVersionRun_4f0f {
  strings:
    $key_4f0f = { 1c 60 [2] 38 6e [2] 13 42 [2] 3d 60 [2] 29 7b [2] 26 61 [2] 38 7c [2] 3a 7d [2] 21 7b [2] 3d 7c [2] 21 53 }

  condition:
    any of them
}