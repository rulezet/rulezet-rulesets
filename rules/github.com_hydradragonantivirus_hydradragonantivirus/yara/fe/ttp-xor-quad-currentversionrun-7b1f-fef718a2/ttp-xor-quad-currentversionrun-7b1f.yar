rule TTP_XOR_QUAD_CurrentVersionRun_7b1f {
  strings:
    $key_7b1f = { 28 70 [2] 0c 7e [2] 27 52 [2] 09 70 [2] 1d 6b [2] 12 71 [2] 0c 6c [2] 0e 6d [2] 15 6b [2] 09 6c [2] 15 43 }

  condition:
    any of them
}