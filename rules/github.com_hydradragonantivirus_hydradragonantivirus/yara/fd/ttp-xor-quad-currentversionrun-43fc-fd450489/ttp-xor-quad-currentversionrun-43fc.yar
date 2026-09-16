rule TTP_XOR_QUAD_CurrentVersionRun_43fc {
  strings:
    $key_43fc = { 10 93 [2] 34 9d [2] 1f b1 [2] 31 93 [2] 25 88 [2] 2a 92 [2] 34 8f [2] 36 8e [2] 2d 88 [2] 31 8f [2] 2d a0 }

  condition:
    any of them
}