rule TTP_XOR_QUAD_CurrentVersionRun_2c4f {
  strings:
    $key_2c4f = { 7f 20 [2] 5b 2e [2] 70 02 [2] 5e 20 [2] 4a 3b [2] 45 21 [2] 5b 3c [2] 59 3d [2] 42 3b [2] 5e 3c [2] 42 13 }

  condition:
    any of them
}