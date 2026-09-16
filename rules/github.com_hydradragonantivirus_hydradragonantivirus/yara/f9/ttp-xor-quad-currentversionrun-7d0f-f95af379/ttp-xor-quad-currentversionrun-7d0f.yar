rule TTP_XOR_QUAD_CurrentVersionRun_7d0f {
  strings:
    $key_7d0f = { 2e 60 [2] 0a 6e [2] 21 42 [2] 0f 60 [2] 1b 7b [2] 14 61 [2] 0a 7c [2] 08 7d [2] 13 7b [2] 0f 7c [2] 13 53 }

  condition:
    any of them
}