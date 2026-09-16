rule TTP_XOR_QUAD_CurrentVersionRun_311f {
  strings:
    $key_311f = { 62 70 [2] 46 7e [2] 6d 52 [2] 43 70 [2] 57 6b [2] 58 71 [2] 46 6c [2] 44 6d [2] 5f 6b [2] 43 6c [2] 5f 43 }

  condition:
    any of them
}