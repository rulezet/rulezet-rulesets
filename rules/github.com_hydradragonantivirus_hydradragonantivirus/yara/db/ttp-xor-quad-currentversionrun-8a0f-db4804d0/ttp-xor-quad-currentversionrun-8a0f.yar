rule TTP_XOR_QUAD_CurrentVersionRun_8a0f {
  strings:
    $key_8a0f = { d9 60 [2] fd 6e [2] d6 42 [2] f8 60 [2] ec 7b [2] e3 61 [2] fd 7c [2] ff 7d [2] e4 7b [2] f8 7c [2] e4 53 }

  condition:
    any of them
}