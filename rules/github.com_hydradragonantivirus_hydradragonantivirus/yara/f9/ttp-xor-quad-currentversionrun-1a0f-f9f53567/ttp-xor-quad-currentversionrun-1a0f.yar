rule TTP_XOR_QUAD_CurrentVersionRun_1a0f {
  strings:
    $key_1a0f = { 49 60 [2] 6d 6e [2] 46 42 [2] 68 60 [2] 7c 7b [2] 73 61 [2] 6d 7c [2] 6f 7d [2] 74 7b [2] 68 7c [2] 74 53 }

  condition:
    any of them
}