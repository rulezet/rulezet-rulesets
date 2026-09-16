rule TTP_XOR_QUAD_CurrentVersionRun_6b0f {
  strings:
    $key_6b0f = { 38 60 [2] 1c 6e [2] 37 42 [2] 19 60 [2] 0d 7b [2] 02 61 [2] 1c 7c [2] 1e 7d [2] 05 7b [2] 19 7c [2] 05 53 }

  condition:
    any of them
}