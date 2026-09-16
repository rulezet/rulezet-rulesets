rule TTP_XOR_QUAD_CurrentVersionRun_5618 {
  strings:
    $key_5618 = { 05 77 [2] 21 79 [2] 0a 55 [2] 24 77 [2] 30 6c [2] 3f 76 [2] 21 6b [2] 23 6a [2] 38 6c [2] 24 6b [2] 38 44 }

  condition:
    any of them
}