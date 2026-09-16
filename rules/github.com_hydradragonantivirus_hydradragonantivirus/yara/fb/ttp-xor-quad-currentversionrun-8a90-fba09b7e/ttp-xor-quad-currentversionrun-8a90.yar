rule TTP_XOR_QUAD_CurrentVersionRun_8a90 {
  strings:
    $key_8a90 = { d9 ff [2] fd f1 [2] d6 dd [2] f8 ff [2] ec e4 [2] e3 fe [2] fd e3 [2] ff e2 [2] e4 e4 [2] f8 e3 [2] e4 cc }

  condition:
    any of them
}