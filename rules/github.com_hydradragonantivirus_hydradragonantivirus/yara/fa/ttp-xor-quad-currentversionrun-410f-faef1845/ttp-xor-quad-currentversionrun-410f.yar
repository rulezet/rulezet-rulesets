rule TTP_XOR_QUAD_CurrentVersionRun_410f {
  strings:
    $key_410f = { 12 60 [2] 36 6e [2] 1d 42 [2] 33 60 [2] 27 7b [2] 28 61 [2] 36 7c [2] 34 7d [2] 2f 7b [2] 33 7c [2] 2f 53 }

  condition:
    any of them
}