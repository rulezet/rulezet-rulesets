rule TTP_XOR_QUAD_CurrentVersionRun_29ca {
  strings:
    $key_29ca = { 7a a5 [2] 5e ab [2] 75 87 [2] 5b a5 [2] 4f be [2] 40 a4 [2] 5e b9 [2] 5c b8 [2] 47 be [2] 5b b9 [2] 47 96 }

  condition:
    any of them
}