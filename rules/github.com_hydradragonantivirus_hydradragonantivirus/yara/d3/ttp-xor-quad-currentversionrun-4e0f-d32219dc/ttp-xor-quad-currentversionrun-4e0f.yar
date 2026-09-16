rule TTP_XOR_QUAD_CurrentVersionRun_4e0f {
  strings:
    $key_4e0f = { 1d 60 [2] 39 6e [2] 12 42 [2] 3c 60 [2] 28 7b [2] 27 61 [2] 39 7c [2] 3b 7d [2] 20 7b [2] 3c 7c [2] 20 53 }

  condition:
    any of them
}