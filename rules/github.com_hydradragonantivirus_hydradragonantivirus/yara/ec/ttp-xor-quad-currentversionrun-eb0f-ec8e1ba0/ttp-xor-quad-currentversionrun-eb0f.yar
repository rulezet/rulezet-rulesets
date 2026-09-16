rule TTP_XOR_QUAD_CurrentVersionRun_eb0f {
  strings:
    $key_eb0f = { b8 60 [2] 9c 6e [2] b7 42 [2] 99 60 [2] 8d 7b [2] 82 61 [2] 9c 7c [2] 9e 7d [2] 85 7b [2] 99 7c [2] 85 53 }

  condition:
    any of them
}