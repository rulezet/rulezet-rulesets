rule TTP_XOR_QUAD_CurrentVersionRun_deea {
  strings:
    $key_deea = { 8d 85 [2] a9 8b [2] 82 a7 [2] ac 85 [2] b8 9e [2] b7 84 [2] a9 99 [2] ab 98 [2] b0 9e [2] ac 99 [2] b0 b6 }

  condition:
    any of them
}