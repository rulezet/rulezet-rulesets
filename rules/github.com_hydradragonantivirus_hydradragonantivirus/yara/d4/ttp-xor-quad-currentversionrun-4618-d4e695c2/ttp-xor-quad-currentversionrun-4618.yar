rule TTP_XOR_QUAD_CurrentVersionRun_4618 {
  strings:
    $key_4618 = { 15 77 [2] 31 79 [2] 1a 55 [2] 34 77 [2] 20 6c [2] 2f 76 [2] 31 6b [2] 33 6a [2] 28 6c [2] 34 6b [2] 28 44 }

  condition:
    any of them
}