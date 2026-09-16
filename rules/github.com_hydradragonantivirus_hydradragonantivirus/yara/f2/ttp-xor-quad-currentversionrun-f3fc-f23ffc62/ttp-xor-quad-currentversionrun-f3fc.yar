rule TTP_XOR_QUAD_CurrentVersionRun_f3fc {
  strings:
    $key_f3fc = { a0 93 [2] 84 9d [2] af b1 [2] 81 93 [2] 95 88 [2] 9a 92 [2] 84 8f [2] 86 8e [2] 9d 88 [2] 81 8f [2] 9d a0 }

  condition:
    any of them
}