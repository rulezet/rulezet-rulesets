rule TTP_XOR_QUAD_CurrentVersionRun_0c1f {
  strings:
    $key_0c1f = { 5f 70 [2] 7b 7e [2] 50 52 [2] 7e 70 [2] 6a 6b [2] 65 71 [2] 7b 6c [2] 79 6d [2] 62 6b [2] 7e 6c [2] 62 43 }

  condition:
    any of them
}