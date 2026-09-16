rule TTP_XOR_QUAD_CurrentVersionRun_eb0a {
  strings:
    $key_eb0a = { b8 65 [2] 9c 6b [2] b7 47 [2] 99 65 [2] 8d 7e [2] 82 64 [2] 9c 79 [2] 9e 78 [2] 85 7e [2] 99 79 [2] 85 56 }

  condition:
    any of them
}