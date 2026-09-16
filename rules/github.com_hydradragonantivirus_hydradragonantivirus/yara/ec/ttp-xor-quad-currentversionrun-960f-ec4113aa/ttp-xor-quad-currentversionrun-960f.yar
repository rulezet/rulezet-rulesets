rule TTP_XOR_QUAD_CurrentVersionRun_960f {
  strings:
    $key_960f = { c5 60 [2] e1 6e [2] ca 42 [2] e4 60 [2] f0 7b [2] ff 61 [2] e1 7c [2] e3 7d [2] f8 7b [2] e4 7c [2] f8 53 }

  condition:
    any of them
}