rule TTP_XOR_QUAD_CurrentVersionRun_692f {
  strings:
    $key_692f = { 3a 40 [2] 1e 4e [2] 35 62 [2] 1b 40 [2] 0f 5b [2] 00 41 [2] 1e 5c [2] 1c 5d [2] 07 5b [2] 1b 5c [2] 07 73 }

  condition:
    any of them
}