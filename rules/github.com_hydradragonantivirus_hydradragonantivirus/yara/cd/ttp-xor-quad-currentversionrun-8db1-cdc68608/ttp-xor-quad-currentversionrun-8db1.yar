rule TTP_XOR_QUAD_CurrentVersionRun_8db1 {
  strings:
    $key_8db1 = { de de [2] fa d0 [2] d1 fc [2] ff de [2] eb c5 [2] e4 df [2] fa c2 [2] f8 c3 [2] e3 c5 [2] ff c2 [2] e3 ed }

  condition:
    any of them
}