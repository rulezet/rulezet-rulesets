rule TTP_XOR_QUAD_CurrentVersionRun_cd9f {
  strings:
    $key_cd9f = { 9e f0 [2] ba fe [2] 91 d2 [2] bf f0 [2] ab eb [2] a4 f1 [2] ba ec [2] b8 ed [2] a3 eb [2] bf ec [2] a3 c3 }

  condition:
    any of them
}