rule TTP_XOR_QUAD_CurrentVersionRun_f9db {
  strings:
    $key_f9db = { aa b4 [2] 8e ba [2] a5 96 [2] 8b b4 [2] 9f af [2] 90 b5 [2] 8e a8 [2] 8c a9 [2] 97 af [2] 8b a8 [2] 97 87 }

  condition:
    any of them
}