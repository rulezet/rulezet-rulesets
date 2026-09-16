rule TTP_XOR_QUAD_CurrentVersionRun_cada {
  strings:
    $key_cada = { 99 b5 [2] bd bb [2] 96 97 [2] b8 b5 [2] ac ae [2] a3 b4 [2] bd a9 [2] bf a8 [2] a4 ae [2] b8 a9 [2] a4 86 }

  condition:
    any of them
}