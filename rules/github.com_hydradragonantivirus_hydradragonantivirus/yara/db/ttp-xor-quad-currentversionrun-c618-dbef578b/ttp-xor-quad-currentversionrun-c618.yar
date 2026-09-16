rule TTP_XOR_QUAD_CurrentVersionRun_c618 {
  strings:
    $key_c618 = { 95 77 [2] b1 79 [2] 9a 55 [2] b4 77 [2] a0 6c [2] af 76 [2] b1 6b [2] b3 6a [2] a8 6c [2] b4 6b [2] a8 44 }

  condition:
    any of them
}