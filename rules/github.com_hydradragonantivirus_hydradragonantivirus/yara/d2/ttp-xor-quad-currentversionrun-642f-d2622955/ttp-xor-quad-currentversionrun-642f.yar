rule TTP_XOR_QUAD_CurrentVersionRun_642f {
  strings:
    $key_642f = { 37 40 [2] 13 4e [2] 38 62 [2] 16 40 [2] 02 5b [2] 0d 41 [2] 13 5c [2] 11 5d [2] 0a 5b [2] 16 5c [2] 0a 73 }

  condition:
    any of them
}