rule TTP_XOR_QUAD_CurrentVersionRun_e80c {
  strings:
    $key_e80c = { bb 63 [2] 9f 6d [2] b4 41 [2] 9a 63 [2] 8e 78 [2] 81 62 [2] 9f 7f [2] 9d 7e [2] 86 78 [2] 9a 7f [2] 86 50 }

  condition:
    any of them
}