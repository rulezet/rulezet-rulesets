rule TTP_XOR_QUAD_CurrentVersionRun_c571 {
  strings:
    $key_c571 = { 96 1e [2] b2 10 [2] 99 3c [2] b7 1e [2] a3 05 [2] ac 1f [2] b2 02 [2] b0 03 [2] ab 05 [2] b7 02 [2] ab 2d }

  condition:
    any of them
}