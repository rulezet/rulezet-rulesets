rule TTP_XOR_QUAD_CurrentVersionRun_8ee3 {
  strings:
    $key_8ee3 = { dd 8c [2] f9 82 [2] d2 ae [2] fc 8c [2] e8 97 [2] e7 8d [2] f9 90 [2] fb 91 [2] e0 97 [2] fc 90 [2] e0 bf }

  condition:
    any of them
}