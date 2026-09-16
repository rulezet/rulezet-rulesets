rule TTP_XOR_QUAD_CurrentVersionRun_ffda {
  strings:
    $key_ffda = { ac b5 [2] 88 bb [2] a3 97 [2] 8d b5 [2] 99 ae [2] 96 b4 [2] 88 a9 [2] 8a a8 [2] 91 ae [2] 8d a9 [2] 91 86 }

  condition:
    any of them
}