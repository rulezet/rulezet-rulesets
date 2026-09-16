rule TTP_XOR_QUAD_CurrentVersionRun_171f {
  strings:
    $key_171f = { 44 70 [2] 60 7e [2] 4b 52 [2] 65 70 [2] 71 6b [2] 7e 71 [2] 60 6c [2] 62 6d [2] 79 6b [2] 65 6c [2] 79 43 }

  condition:
    any of them
}