rule TTP_XOR_QUAD_CurrentVersionRun_c51f {
  strings:
    $key_c51f = { 96 70 [2] b2 7e [2] 99 52 [2] b7 70 [2] a3 6b [2] ac 71 [2] b2 6c [2] b0 6d [2] ab 6b [2] b7 6c [2] ab 43 }

  condition:
    any of them
}