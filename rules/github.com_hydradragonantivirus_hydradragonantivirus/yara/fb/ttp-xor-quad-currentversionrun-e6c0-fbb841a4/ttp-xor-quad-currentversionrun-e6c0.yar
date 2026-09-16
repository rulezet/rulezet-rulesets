rule TTP_XOR_QUAD_CurrentVersionRun_e6c0 {
  strings:
    $key_e6c0 = { b5 af [2] 91 a1 [2] ba 8d [2] 94 af [2] 80 b4 [2] 8f ae [2] 91 b3 [2] 93 b2 [2] 88 b4 [2] 94 b3 [2] 88 9c }

  condition:
    any of them
}