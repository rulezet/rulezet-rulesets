rule TTP_XOR_QUAD_CurrentVersionRun_fdf2 {
  strings:
    $key_fdf2 = { ae 9d [2] 8a 93 [2] a1 bf [2] 8f 9d [2] 9b 86 [2] 94 9c [2] 8a 81 [2] 88 80 [2] 93 86 [2] 8f 81 [2] 93 ae }

  condition:
    any of them
}