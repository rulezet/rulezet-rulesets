rule TTP_XOR_QUAD_CurrentVersionRun_e60a {
  strings:
    $key_e60a = { b5 65 [2] 91 6b [2] ba 47 [2] 94 65 [2] 80 7e [2] 8f 64 [2] 91 79 [2] 93 78 [2] 88 7e [2] 94 79 [2] 88 56 }

  condition:
    any of them
}