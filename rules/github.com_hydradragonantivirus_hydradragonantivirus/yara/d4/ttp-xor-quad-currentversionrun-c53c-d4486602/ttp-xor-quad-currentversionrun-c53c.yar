rule TTP_XOR_QUAD_CurrentVersionRun_c53c {
  strings:
    $key_c53c = { 96 53 [2] b2 5d [2] 99 71 [2] b7 53 [2] a3 48 [2] ac 52 [2] b2 4f [2] b0 4e [2] ab 48 [2] b7 4f [2] ab 60 }

  condition:
    any of them
}