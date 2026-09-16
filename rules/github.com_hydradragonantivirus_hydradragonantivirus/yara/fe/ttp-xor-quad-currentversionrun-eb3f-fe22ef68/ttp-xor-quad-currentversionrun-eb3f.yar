rule TTP_XOR_QUAD_CurrentVersionRun_eb3f {
  strings:
    $key_eb3f = { b8 50 [2] 9c 5e [2] b7 72 [2] 99 50 [2] 8d 4b [2] 82 51 [2] 9c 4c [2] 9e 4d [2] 85 4b [2] 99 4c [2] 85 63 }

  condition:
    any of them
}