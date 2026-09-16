rule TTP_XOR_QUAD_CurrentVersionRun_e80a {
  strings:
    $key_e80a = { bb 65 [2] 9f 6b [2] b4 47 [2] 9a 65 [2] 8e 7e [2] 81 64 [2] 9f 79 [2] 9d 78 [2] 86 7e [2] 9a 79 [2] 86 56 }

  condition:
    any of them
}