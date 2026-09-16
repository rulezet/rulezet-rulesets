rule TTP_XOR_QUAD_CurrentVersionRun_d618 {
  strings:
    $key_d618 = { 85 77 [2] a1 79 [2] 8a 55 [2] a4 77 [2] b0 6c [2] bf 76 [2] a1 6b [2] a3 6a [2] b8 6c [2] a4 6b [2] b8 44 }

  condition:
    any of them
}