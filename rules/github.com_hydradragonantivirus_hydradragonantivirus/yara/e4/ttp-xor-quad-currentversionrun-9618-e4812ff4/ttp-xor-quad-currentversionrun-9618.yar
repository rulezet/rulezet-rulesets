rule TTP_XOR_QUAD_CurrentVersionRun_9618 {
  strings:
    $key_9618 = { c5 77 [2] e1 79 [2] ca 55 [2] e4 77 [2] f0 6c [2] ff 76 [2] e1 6b [2] e3 6a [2] f8 6c [2] e4 6b [2] f8 44 }

  condition:
    any of them
}