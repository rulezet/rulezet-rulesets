rule TTP_XOR_QUAD_CurrentVersionRun_3e2f {
  strings:
    $key_3e2f = { 6d 40 [2] 49 4e [2] 62 62 [2] 4c 40 [2] 58 5b [2] 57 41 [2] 49 5c [2] 4b 5d [2] 50 5b [2] 4c 5c [2] 50 73 }

  condition:
    any of them
}