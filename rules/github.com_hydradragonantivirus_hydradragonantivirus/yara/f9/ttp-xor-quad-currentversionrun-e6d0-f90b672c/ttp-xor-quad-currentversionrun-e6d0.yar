rule TTP_XOR_QUAD_CurrentVersionRun_e6d0 {
  strings:
    $key_e6d0 = { b5 bf [2] 91 b1 [2] ba 9d [2] 94 bf [2] 80 a4 [2] 8f be [2] 91 a3 [2] 93 a2 [2] 88 a4 [2] 94 a3 [2] 88 8c }

  condition:
    any of them
}