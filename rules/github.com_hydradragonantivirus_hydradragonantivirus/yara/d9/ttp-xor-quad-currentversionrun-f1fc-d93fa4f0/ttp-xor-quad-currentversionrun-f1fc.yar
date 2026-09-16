rule TTP_XOR_QUAD_CurrentVersionRun_f1fc {
  strings:
    $key_f1fc = { a2 93 [2] 86 9d [2] ad b1 [2] 83 93 [2] 97 88 [2] 98 92 [2] 86 8f [2] 84 8e [2] 9f 88 [2] 83 8f [2] 9f a0 }

  condition:
    any of them
}