rule TTP_XOR_QUAD_CurrentVersionRun_21fc {
  strings:
    $key_21fc = { 72 93 [2] 56 9d [2] 7d b1 [2] 53 93 [2] 47 88 [2] 48 92 [2] 56 8f [2] 54 8e [2] 4f 88 [2] 53 8f [2] 4f a0 }

  condition:
    any of them
}