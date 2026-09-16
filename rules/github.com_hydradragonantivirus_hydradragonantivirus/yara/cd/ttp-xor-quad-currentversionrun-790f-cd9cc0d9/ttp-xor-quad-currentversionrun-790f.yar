rule TTP_XOR_QUAD_CurrentVersionRun_790f {
  strings:
    $key_790f = { 2a 60 [2] 0e 6e [2] 25 42 [2] 0b 60 [2] 1f 7b [2] 10 61 [2] 0e 7c [2] 0c 7d [2] 17 7b [2] 0b 7c [2] 17 53 }

  condition:
    any of them
}