rule TTP_XOR_QUAD_CurrentVersionRun_8d02 {
  strings:
    $key_8d02 = { de 6d [2] fa 63 [2] d1 4f [2] ff 6d [2] eb 76 [2] e4 6c [2] fa 71 [2] f8 70 [2] e3 76 [2] ff 71 [2] e3 5e }

  condition:
    any of them
}