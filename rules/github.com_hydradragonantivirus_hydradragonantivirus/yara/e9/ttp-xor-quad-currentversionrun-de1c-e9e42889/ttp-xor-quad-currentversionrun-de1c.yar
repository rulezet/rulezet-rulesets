rule TTP_XOR_QUAD_CurrentVersionRun_de1c {
  strings:
    $key_de1c = { 8d 73 [2] a9 7d [2] 82 51 [2] ac 73 [2] b8 68 [2] b7 72 [2] a9 6f [2] ab 6e [2] b0 68 [2] ac 6f [2] b0 40 }

  condition:
    any of them
}