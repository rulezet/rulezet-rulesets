rule TTP_XOR_QUAD_CurrentVersionRun_cd06 {
  strings:
    $key_cd06 = { 9e 69 [2] ba 67 [2] 91 4b [2] bf 69 [2] ab 72 [2] a4 68 [2] ba 75 [2] b8 74 [2] a3 72 [2] bf 75 [2] a3 5a }

  condition:
    any of them
}