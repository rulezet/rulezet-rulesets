rule TTP_XOR_QUAD_CurrentVersionRun_1d1f {
  strings:
    $key_1d1f = { 4e 70 [2] 6a 7e [2] 41 52 [2] 6f 70 [2] 7b 6b [2] 74 71 [2] 6a 6c [2] 68 6d [2] 73 6b [2] 6f 6c [2] 73 43 }

  condition:
    any of them
}