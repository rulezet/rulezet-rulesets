rule TTP_XOR_QUAD_CurrentVersionRun_6a1f {
  strings:
    $key_6a1f = { 39 70 [2] 1d 7e [2] 36 52 [2] 18 70 [2] 0c 6b [2] 03 71 [2] 1d 6c [2] 1f 6d [2] 04 6b [2] 18 6c [2] 04 43 }

  condition:
    any of them
}