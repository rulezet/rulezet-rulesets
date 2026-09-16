rule TTP_XOR_QUAD_CurrentVersionRun_c2ec {
  strings:
    $key_c2ec = { 91 83 [2] b5 8d [2] 9e a1 [2] b0 83 [2] a4 98 [2] ab 82 [2] b5 9f [2] b7 9e [2] ac 98 [2] b0 9f [2] ac b0 }

  condition:
    any of them
}