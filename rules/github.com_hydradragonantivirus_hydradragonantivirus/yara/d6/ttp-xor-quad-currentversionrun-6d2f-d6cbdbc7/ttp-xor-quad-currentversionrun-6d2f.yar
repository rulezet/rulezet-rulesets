rule TTP_XOR_QUAD_CurrentVersionRun_6d2f {
  strings:
    $key_6d2f = { 3e 40 [2] 1a 4e [2] 31 62 [2] 1f 40 [2] 0b 5b [2] 04 41 [2] 1a 5c [2] 18 5d [2] 03 5b [2] 1f 5c [2] 03 73 }

  condition:
    any of them
}