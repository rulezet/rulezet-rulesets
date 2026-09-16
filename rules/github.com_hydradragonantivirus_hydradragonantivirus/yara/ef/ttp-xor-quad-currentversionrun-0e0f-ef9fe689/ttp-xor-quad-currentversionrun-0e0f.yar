rule TTP_XOR_QUAD_CurrentVersionRun_0e0f {
  strings:
    $key_0e0f = { 5d 60 [2] 79 6e [2] 52 42 [2] 7c 60 [2] 68 7b [2] 67 61 [2] 79 7c [2] 7b 7d [2] 60 7b [2] 7c 7c [2] 60 53 }

  condition:
    any of them
}