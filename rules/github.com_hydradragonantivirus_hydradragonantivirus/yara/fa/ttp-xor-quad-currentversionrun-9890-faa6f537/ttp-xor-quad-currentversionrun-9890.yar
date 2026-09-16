rule TTP_XOR_QUAD_CurrentVersionRun_9890 {
  strings:
    $key_9890 = { cb ff [2] ef f1 [2] c4 dd [2] ea ff [2] fe e4 [2] f1 fe [2] ef e3 [2] ed e2 [2] f6 e4 [2] ea e3 [2] f6 cc }

  condition:
    any of them
}