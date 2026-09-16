rule TTP_XOR_QUAD_CurrentVersionRun_29da {
  strings:
    $key_29da = { 7a b5 [2] 5e bb [2] 75 97 [2] 5b b5 [2] 4f ae [2] 40 b4 [2] 5e a9 [2] 5c a8 [2] 47 ae [2] 5b a9 [2] 47 86 }

  condition:
    any of them
}