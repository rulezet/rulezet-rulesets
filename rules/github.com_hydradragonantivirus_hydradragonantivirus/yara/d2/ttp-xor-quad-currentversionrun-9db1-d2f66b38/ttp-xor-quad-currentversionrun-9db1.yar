rule TTP_XOR_QUAD_CurrentVersionRun_9db1 {
  strings:
    $key_9db1 = { ce de [2] ea d0 [2] c1 fc [2] ef de [2] fb c5 [2] f4 df [2] ea c2 [2] e8 c3 [2] f3 c5 [2] ef c2 [2] f3 ed }

  condition:
    any of them
}