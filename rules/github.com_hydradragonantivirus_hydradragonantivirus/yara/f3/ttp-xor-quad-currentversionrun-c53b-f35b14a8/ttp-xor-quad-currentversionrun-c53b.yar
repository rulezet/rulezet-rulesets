rule TTP_XOR_QUAD_CurrentVersionRun_c53b {
  strings:
    $key_c53b = { 96 54 [2] b2 5a [2] 99 76 [2] b7 54 [2] a3 4f [2] ac 55 [2] b2 48 [2] b0 49 [2] ab 4f [2] b7 48 [2] ab 67 }

  condition:
    any of them
}