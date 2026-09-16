rule TTP_XOR_QUAD_CurrentVersionRun_d12e {
  strings:
    $key_d12e = { 82 41 [2] a6 4f [2] 8d 63 [2] a3 41 [2] b7 5a [2] b8 40 [2] a6 5d [2] a4 5c [2] bf 5a [2] a3 5d [2] bf 72 }

  condition:
    any of them
}