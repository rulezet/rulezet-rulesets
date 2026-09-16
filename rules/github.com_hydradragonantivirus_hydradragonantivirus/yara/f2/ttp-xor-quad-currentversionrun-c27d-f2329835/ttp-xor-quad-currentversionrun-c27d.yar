rule TTP_XOR_QUAD_CurrentVersionRun_c27d {
  strings:
    $key_c27d = { 91 12 [2] b5 1c [2] 9e 30 [2] b0 12 [2] a4 09 [2] ab 13 [2] b5 0e [2] b7 0f [2] ac 09 [2] b0 0e [2] ac 21 }

  condition:
    any of them
}