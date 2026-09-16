rule TTP_XOR_QUAD_CurrentVersionRun_ab00 {
  strings:
    $key_ab00 = { f8 6f [2] dc 61 [2] f7 4d [2] d9 6f [2] cd 74 [2] c2 6e [2] dc 73 [2] de 72 [2] c5 74 [2] d9 73 [2] c5 5c }

  condition:
    any of them
}