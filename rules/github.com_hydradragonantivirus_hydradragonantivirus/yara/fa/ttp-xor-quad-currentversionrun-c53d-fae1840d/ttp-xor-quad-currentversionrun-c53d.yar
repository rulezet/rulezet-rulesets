rule TTP_XOR_QUAD_CurrentVersionRun_c53d {
  strings:
    $key_c53d = { 96 52 [2] b2 5c [2] 99 70 [2] b7 52 [2] a3 49 [2] ac 53 [2] b2 4e [2] b0 4f [2] ab 49 [2] b7 4e [2] ab 61 }

  condition:
    any of them
}