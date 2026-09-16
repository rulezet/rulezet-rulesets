rule TTP_XOR_QUAD_CurrentVersionRun_ab31 {
  strings:
    $key_ab31 = { f8 5e [2] dc 50 [2] f7 7c [2] d9 5e [2] cd 45 [2] c2 5f [2] dc 42 [2] de 43 [2] c5 45 [2] d9 42 [2] c5 6d }

  condition:
    any of them
}