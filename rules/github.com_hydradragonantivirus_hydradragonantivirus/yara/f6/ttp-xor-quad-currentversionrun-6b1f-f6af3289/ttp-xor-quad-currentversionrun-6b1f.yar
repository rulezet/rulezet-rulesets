rule TTP_XOR_QUAD_CurrentVersionRun_6b1f {
  strings:
    $key_6b1f = { 38 70 [2] 1c 7e [2] 37 52 [2] 19 70 [2] 0d 6b [2] 02 71 [2] 1c 6c [2] 1e 6d [2] 05 6b [2] 19 6c [2] 05 43 }

  condition:
    any of them
}