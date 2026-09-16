rule TTP_XOR_QUAD_CurrentVersionRun_29af {
  strings:
    $key_29af = { 7a c0 [2] 5e ce [2] 75 e2 [2] 5b c0 [2] 4f db [2] 40 c1 [2] 5e dc [2] 5c dd [2] 47 db [2] 5b dc [2] 47 f3 }

  condition:
    any of them
}