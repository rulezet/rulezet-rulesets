rule TTP_XOR_QUAD_CurrentVersionRun_6a0f {
  strings:
    $key_6a0f = { 39 60 [2] 1d 6e [2] 36 42 [2] 18 60 [2] 0c 7b [2] 03 61 [2] 1d 7c [2] 1f 7d [2] 04 7b [2] 18 7c [2] 04 53 }

  condition:
    any of them
}