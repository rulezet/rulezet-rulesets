rule TTP_XOR_QUAD_CurrentVersionRun_8afe {
  strings:
    $key_8afe = { d9 91 [2] fd 9f [2] d6 b3 [2] f8 91 [2] ec 8a [2] e3 90 [2] fd 8d [2] ff 8c [2] e4 8a [2] f8 8d [2] e4 a2 }

  condition:
    any of them
}