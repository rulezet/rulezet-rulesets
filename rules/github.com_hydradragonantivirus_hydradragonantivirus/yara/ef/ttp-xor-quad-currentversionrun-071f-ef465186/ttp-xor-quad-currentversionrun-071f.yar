rule TTP_XOR_QUAD_CurrentVersionRun_071f {
  strings:
    $key_071f = { 54 70 [2] 70 7e [2] 5b 52 [2] 75 70 [2] 61 6b [2] 6e 71 [2] 70 6c [2] 72 6d [2] 69 6b [2] 75 6c [2] 69 43 }

  condition:
    any of them
}