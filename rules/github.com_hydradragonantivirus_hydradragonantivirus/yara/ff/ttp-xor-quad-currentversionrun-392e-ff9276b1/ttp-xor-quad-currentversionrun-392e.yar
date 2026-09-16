rule TTP_XOR_QUAD_CurrentVersionRun_392e {
  strings:
    $key_392e = { 6a 41 [2] 4e 4f [2] 65 63 [2] 4b 41 [2] 5f 5a [2] 50 40 [2] 4e 5d [2] 4c 5c [2] 57 5a [2] 4b 5d [2] 57 72 }

  condition:
    any of them
}