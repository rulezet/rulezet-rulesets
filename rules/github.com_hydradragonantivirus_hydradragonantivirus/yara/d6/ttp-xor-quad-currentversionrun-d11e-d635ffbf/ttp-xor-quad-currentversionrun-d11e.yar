rule TTP_XOR_QUAD_CurrentVersionRun_d11e {
  strings:
    $key_d11e = { 82 71 [2] a6 7f [2] 8d 53 [2] a3 71 [2] b7 6a [2] b8 70 [2] a6 6d [2] a4 6c [2] bf 6a [2] a3 6d [2] bf 42 }

  condition:
    any of them
}