rule TTP_XOR_QUAD_CurrentVersionRun_d396 {
  strings:
    $key_d396 = { 80 f9 [2] a4 f7 [2] 8f db [2] a1 f9 [2] b5 e2 [2] ba f8 [2] a4 e5 [2] a6 e4 [2] bd e2 [2] a1 e5 [2] bd ca }

  condition:
    any of them
}