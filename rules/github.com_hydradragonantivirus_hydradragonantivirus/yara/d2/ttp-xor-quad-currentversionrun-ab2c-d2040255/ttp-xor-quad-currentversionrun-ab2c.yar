rule TTP_XOR_QUAD_CurrentVersionRun_ab2c {
  strings:
    $key_ab2c = { f8 43 [2] dc 4d [2] f7 61 [2] d9 43 [2] cd 58 [2] c2 42 [2] dc 5f [2] de 5e [2] c5 58 [2] d9 5f [2] c5 70 }

  condition:
    any of them
}