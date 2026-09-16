rule TTP_XOR_QUAD_CurrentVersionRun_762f {
  strings:
    $key_762f = { 25 40 [2] 01 4e [2] 2a 62 [2] 04 40 [2] 10 5b [2] 1f 41 [2] 01 5c [2] 03 5d [2] 18 5b [2] 04 5c [2] 18 73 }

  condition:
    any of them
}