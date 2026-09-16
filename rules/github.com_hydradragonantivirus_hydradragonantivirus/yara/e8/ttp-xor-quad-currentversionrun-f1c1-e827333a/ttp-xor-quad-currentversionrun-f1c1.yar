rule TTP_XOR_QUAD_CurrentVersionRun_f1c1 {
  strings:
    $key_f1c1 = { a2 ae [2] 86 a0 [2] ad 8c [2] 83 ae [2] 97 b5 [2] 98 af [2] 86 b2 [2] 84 b3 [2] 9f b5 [2] 83 b2 [2] 9f 9d }

  condition:
    any of them
}