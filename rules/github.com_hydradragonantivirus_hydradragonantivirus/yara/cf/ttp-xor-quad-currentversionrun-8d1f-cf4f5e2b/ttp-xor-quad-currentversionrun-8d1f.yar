rule TTP_XOR_QUAD_CurrentVersionRun_8d1f {
  strings:
    $key_8d1f = { de 70 [2] fa 7e [2] d1 52 [2] ff 70 [2] eb 6b [2] e4 71 [2] fa 6c [2] f8 6d [2] e3 6b [2] ff 6c [2] e3 43 }

  condition:
    any of them
}