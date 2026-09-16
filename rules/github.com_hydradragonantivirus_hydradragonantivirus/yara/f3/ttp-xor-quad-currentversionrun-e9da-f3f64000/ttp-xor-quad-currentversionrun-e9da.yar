rule TTP_XOR_QUAD_CurrentVersionRun_e9da {
  strings:
    $key_e9da = { ba b5 [2] 9e bb [2] b5 97 [2] 9b b5 [2] 8f ae [2] 80 b4 [2] 9e a9 [2] 9c a8 [2] 87 ae [2] 9b a9 [2] 87 86 }

  condition:
    any of them
}