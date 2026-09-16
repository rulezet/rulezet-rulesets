rule TTP_XOR_QUAD_CurrentVersionRun_662f {
  strings:
    $key_662f = { 35 40 [2] 11 4e [2] 3a 62 [2] 14 40 [2] 00 5b [2] 0f 41 [2] 11 5c [2] 13 5d [2] 08 5b [2] 14 5c [2] 08 73 }

  condition:
    any of them
}