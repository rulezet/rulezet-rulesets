rule TTP_XOR_QUAD_CurrentVersionRun_48fc {
  strings:
    $key_48fc = { 1b 93 [2] 3f 9d [2] 14 b1 [2] 3a 93 [2] 2e 88 [2] 21 92 [2] 3f 8f [2] 3d 8e [2] 26 88 [2] 3a 8f [2] 26 a0 }

  condition:
    any of them
}