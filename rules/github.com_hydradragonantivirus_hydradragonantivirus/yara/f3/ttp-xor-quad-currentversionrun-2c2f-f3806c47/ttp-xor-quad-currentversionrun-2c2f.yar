rule TTP_XOR_QUAD_CurrentVersionRun_2c2f {
  strings:
    $key_2c2f = { 7f 40 [2] 5b 4e [2] 70 62 [2] 5e 40 [2] 4a 5b [2] 45 41 [2] 5b 5c [2] 59 5d [2] 42 5b [2] 5e 5c [2] 42 73 }

  condition:
    any of them
}