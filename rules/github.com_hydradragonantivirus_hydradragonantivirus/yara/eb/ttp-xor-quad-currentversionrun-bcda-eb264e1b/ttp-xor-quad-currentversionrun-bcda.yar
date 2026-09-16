rule TTP_XOR_QUAD_CurrentVersionRun_bcda {
  strings:
    $key_bcda = { ef b5 [2] cb bb [2] e0 97 [2] ce b5 [2] da ae [2] d5 b4 [2] cb a9 [2] c9 a8 [2] d2 ae [2] ce a9 [2] d2 86 }

  condition:
    any of them
}