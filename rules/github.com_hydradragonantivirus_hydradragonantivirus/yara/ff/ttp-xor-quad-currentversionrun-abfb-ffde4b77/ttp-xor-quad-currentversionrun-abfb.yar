rule TTP_XOR_QUAD_CurrentVersionRun_abfb {
  strings:
    $key_abfb = { f8 94 [2] dc 9a [2] f7 b6 [2] d9 94 [2] cd 8f [2] c2 95 [2] dc 88 [2] de 89 [2] c5 8f [2] d9 88 [2] c5 a7 }

  condition:
    any of them
}