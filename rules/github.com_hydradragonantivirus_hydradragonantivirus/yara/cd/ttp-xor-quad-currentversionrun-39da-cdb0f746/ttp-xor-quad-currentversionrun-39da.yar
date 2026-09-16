rule TTP_XOR_QUAD_CurrentVersionRun_39da {
  strings:
    $key_39da = { 6a b5 [2] 4e bb [2] 65 97 [2] 4b b5 [2] 5f ae [2] 50 b4 [2] 4e a9 [2] 4c a8 [2] 57 ae [2] 4b a9 [2] 57 86 }

  condition:
    any of them
}