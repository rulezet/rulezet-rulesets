rule TTP_XOR_QUAD_CurrentVersionRun_1290 {
  strings:
    $key_1290 = { 41 ff [2] 65 f1 [2] 4e dd [2] 60 ff [2] 74 e4 [2] 7b fe [2] 65 e3 [2] 67 e2 [2] 7c e4 [2] 60 e3 [2] 7c cc }

  condition:
    any of them
}