rule TTP_XOR_QUAD_CurrentVersionRun_de2f {
  strings:
    $key_de2f = { 8d 40 [2] a9 4e [2] 82 62 [2] ac 40 [2] b8 5b [2] b7 41 [2] a9 5c [2] ab 5d [2] b0 5b [2] ac 5c [2] b0 73 }

  condition:
    any of them
}