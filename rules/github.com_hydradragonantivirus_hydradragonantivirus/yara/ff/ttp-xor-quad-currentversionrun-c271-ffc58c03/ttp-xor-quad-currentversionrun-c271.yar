rule TTP_XOR_QUAD_CurrentVersionRun_c271 {
  strings:
    $key_c271 = { 91 1e [2] b5 10 [2] 9e 3c [2] b0 1e [2] a4 05 [2] ab 1f [2] b5 02 [2] b7 03 [2] ac 05 [2] b0 02 [2] ac 2d }

  condition:
    any of them
}