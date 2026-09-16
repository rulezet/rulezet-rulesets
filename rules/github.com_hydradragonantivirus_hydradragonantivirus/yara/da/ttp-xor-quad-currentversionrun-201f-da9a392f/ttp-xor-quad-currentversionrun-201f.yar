rule TTP_XOR_QUAD_CurrentVersionRun_201f {
  strings:
    $key_201f = { 73 70 [2] 57 7e [2] 7c 52 [2] 52 70 [2] 46 6b [2] 49 71 [2] 57 6c [2] 55 6d [2] 4e 6b [2] 52 6c [2] 4e 43 }

  condition:
    any of them
}