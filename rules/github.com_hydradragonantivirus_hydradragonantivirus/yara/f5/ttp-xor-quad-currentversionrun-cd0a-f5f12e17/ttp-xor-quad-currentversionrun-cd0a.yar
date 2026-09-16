rule TTP_XOR_QUAD_CurrentVersionRun_cd0a {
  strings:
    $key_cd0a = { 9e 65 [2] ba 6b [2] 91 47 [2] bf 65 [2] ab 7e [2] a4 64 [2] ba 79 [2] b8 78 [2] a3 7e [2] bf 79 [2] a3 56 }

  condition:
    any of them
}