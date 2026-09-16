rule TTP_XOR_QUAD_CurrentVersionRun_022f {
  strings:
    $key_022f = { 51 40 [2] 75 4e [2] 5e 62 [2] 70 40 [2] 64 5b [2] 6b 41 [2] 75 5c [2] 77 5d [2] 6c 5b [2] 70 5c [2] 6c 73 }

  condition:
    any of them
}