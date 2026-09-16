rule TTP_XOR_QUAD_CurrentVersionRun_6f0f {
  strings:
    $key_6f0f = { 3c 60 [2] 18 6e [2] 33 42 [2] 1d 60 [2] 09 7b [2] 06 61 [2] 18 7c [2] 1a 7d [2] 01 7b [2] 1d 7c [2] 01 53 }

  condition:
    any of them
}