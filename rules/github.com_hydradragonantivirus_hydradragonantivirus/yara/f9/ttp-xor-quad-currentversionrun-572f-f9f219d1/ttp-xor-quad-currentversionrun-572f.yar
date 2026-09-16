rule TTP_XOR_QUAD_CurrentVersionRun_572f {
  strings:
    $key_572f = { 04 40 [2] 20 4e [2] 0b 62 [2] 25 40 [2] 31 5b [2] 3e 41 [2] 20 5c [2] 22 5d [2] 39 5b [2] 25 5c [2] 39 73 }

  condition:
    any of them
}