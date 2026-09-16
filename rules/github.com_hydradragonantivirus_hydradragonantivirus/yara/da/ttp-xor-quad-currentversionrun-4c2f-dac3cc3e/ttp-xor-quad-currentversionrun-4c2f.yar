rule TTP_XOR_QUAD_CurrentVersionRun_4c2f {
  strings:
    $key_4c2f = { 1f 40 [2] 3b 4e [2] 10 62 [2] 3e 40 [2] 2a 5b [2] 25 41 [2] 3b 5c [2] 39 5d [2] 22 5b [2] 3e 5c [2] 22 73 }

  condition:
    any of them
}