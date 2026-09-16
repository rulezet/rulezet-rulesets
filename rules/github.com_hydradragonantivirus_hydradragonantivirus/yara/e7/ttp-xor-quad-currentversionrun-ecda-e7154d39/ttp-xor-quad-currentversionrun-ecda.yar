rule TTP_XOR_QUAD_CurrentVersionRun_ecda {
  strings:
    $key_ecda = { bf b5 [2] 9b bb [2] b0 97 [2] 9e b5 [2] 8a ae [2] 85 b4 [2] 9b a9 [2] 99 a8 [2] 82 ae [2] 9e a9 [2] 82 86 }

  condition:
    any of them
}