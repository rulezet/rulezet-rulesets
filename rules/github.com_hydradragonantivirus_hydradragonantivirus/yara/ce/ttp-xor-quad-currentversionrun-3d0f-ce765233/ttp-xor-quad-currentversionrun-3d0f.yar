rule TTP_XOR_QUAD_CurrentVersionRun_3d0f {
  strings:
    $key_3d0f = { 6e 60 [2] 4a 6e [2] 61 42 [2] 4f 60 [2] 5b 7b [2] 54 61 [2] 4a 7c [2] 48 7d [2] 53 7b [2] 4f 7c [2] 53 53 }

  condition:
    any of them
}