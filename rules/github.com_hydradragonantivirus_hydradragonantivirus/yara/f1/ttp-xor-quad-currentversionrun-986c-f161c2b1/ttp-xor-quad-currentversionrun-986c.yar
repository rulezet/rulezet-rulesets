rule TTP_XOR_QUAD_CurrentVersionRun_986c {
  strings:
    $key_986c = { cb 03 [2] ef 0d [2] c4 21 [2] ea 03 [2] fe 18 [2] f1 02 [2] ef 1f [2] ed 1e [2] f6 18 [2] ea 1f [2] f6 30 }

  condition:
    any of them
}