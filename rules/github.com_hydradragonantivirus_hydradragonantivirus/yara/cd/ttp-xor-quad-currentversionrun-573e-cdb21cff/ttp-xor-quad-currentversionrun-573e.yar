rule TTP_XOR_QUAD_CurrentVersionRun_573e {
  strings:
    $key_573e = { 04 51 [2] 20 5f [2] 0b 73 [2] 25 51 [2] 31 4a [2] 3e 50 [2] 20 4d [2] 22 4c [2] 39 4a [2] 25 4d [2] 39 62 }

  condition:
    any of them
}