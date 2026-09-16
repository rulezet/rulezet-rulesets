rule TTP_XOR_QUAD_CurrentVersionRun_e32e {
  strings:
    $key_e32e = { b0 41 [2] 94 4f [2] bf 63 [2] 91 41 [2] 85 5a [2] 8a 40 [2] 94 5d [2] 96 5c [2] 8d 5a [2] 91 5d [2] 8d 72 }

  condition:
    any of them
}