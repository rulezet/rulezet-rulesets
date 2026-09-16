rule TTP_XOR_QUAD_CurrentVersionRun_0c0f {
  strings:
    $key_0c0f = { 5f 60 [2] 7b 6e [2] 50 42 [2] 7e 60 [2] 6a 7b [2] 65 61 [2] 7b 7c [2] 79 7d [2] 62 7b [2] 7e 7c [2] 62 53 }

  condition:
    any of them
}