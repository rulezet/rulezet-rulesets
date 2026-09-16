rule TTP_XOR_QUAD_CurrentVersionRun_cd3c {
  strings:
    $key_cd3c = { 9e 53 [2] ba 5d [2] 91 71 [2] bf 53 [2] ab 48 [2] a4 52 [2] ba 4f [2] b8 4e [2] a3 48 [2] bf 4f [2] a3 60 }

  condition:
    any of them
}