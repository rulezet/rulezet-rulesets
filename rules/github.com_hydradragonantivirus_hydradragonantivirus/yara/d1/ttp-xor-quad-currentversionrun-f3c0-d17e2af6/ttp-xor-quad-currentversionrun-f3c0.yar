rule TTP_XOR_QUAD_CurrentVersionRun_f3c0 {
  strings:
    $key_f3c0 = { a0 af [2] 84 a1 [2] af 8d [2] 81 af [2] 95 b4 [2] 9a ae [2] 84 b3 [2] 86 b2 [2] 9d b4 [2] 81 b3 [2] 9d 9c }

  condition:
    any of them
}