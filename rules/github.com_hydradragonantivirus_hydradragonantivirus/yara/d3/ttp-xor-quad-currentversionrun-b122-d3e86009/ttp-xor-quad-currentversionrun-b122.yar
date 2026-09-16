rule TTP_XOR_QUAD_CurrentVersionRun_b122 {
  strings:
    $key_b122 = { e2 4d [2] c6 43 [2] ed 6f [2] c3 4d [2] d7 56 [2] d8 4c [2] c6 51 [2] c4 50 [2] df 56 [2] c3 51 [2] df 7e }

  condition:
    any of them
}