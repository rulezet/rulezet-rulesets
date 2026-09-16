rule TTP_XOR_QUAD_CurrentVersionRun_e80d {
  strings:
    $key_e80d = { bb 62 [2] 9f 6c [2] b4 40 [2] 9a 62 [2] 8e 79 [2] 81 63 [2] 9f 7e [2] 9d 7f [2] 86 79 [2] 9a 7e [2] 86 51 }

  condition:
    any of them
}