rule TTP_XOR_QUAD_CurrentVersionRun_24da {
  strings:
    $key_24da = { 77 b5 [2] 53 bb [2] 78 97 [2] 56 b5 [2] 42 ae [2] 4d b4 [2] 53 a9 [2] 51 a8 [2] 4a ae [2] 56 a9 [2] 4a 86 }

  condition:
    any of them
}