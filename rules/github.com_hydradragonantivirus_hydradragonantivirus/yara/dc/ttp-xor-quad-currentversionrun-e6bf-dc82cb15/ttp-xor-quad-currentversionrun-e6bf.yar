rule TTP_XOR_QUAD_CurrentVersionRun_e6bf {
  strings:
    $key_e6bf = { b5 d0 [2] 91 de [2] ba f2 [2] 94 d0 [2] 80 cb [2] 8f d1 [2] 91 cc [2] 93 cd [2] 88 cb [2] 94 cc [2] 88 e3 }

  condition:
    any of them
}