rule TTP_XOR_QUAD_CurrentVersionRun_f1c0 {
  strings:
    $key_f1c0 = { a2 af [2] 86 a1 [2] ad 8d [2] 83 af [2] 97 b4 [2] 98 ae [2] 86 b3 [2] 84 b2 [2] 9f b4 [2] 83 b3 [2] 9f 9c }

  condition:
    any of them
}