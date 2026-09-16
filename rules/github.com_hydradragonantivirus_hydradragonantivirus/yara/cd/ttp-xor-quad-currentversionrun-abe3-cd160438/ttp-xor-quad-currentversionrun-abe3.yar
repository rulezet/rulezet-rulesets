rule TTP_XOR_QUAD_CurrentVersionRun_abe3 {
  strings:
    $key_abe3 = { f8 8c [2] dc 82 [2] f7 ae [2] d9 8c [2] cd 97 [2] c2 8d [2] dc 90 [2] de 91 [2] c5 97 [2] d9 90 [2] c5 bf }

  condition:
    any of them
}