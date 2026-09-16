rule TTP_XOR_QUAD_CurrentVersionRun_acb3 {
  strings:
    $key_acb3 = { ff dc [2] db d2 [2] f0 fe [2] de dc [2] ca c7 [2] c5 dd [2] db c0 [2] d9 c1 [2] c2 c7 [2] de c0 [2] c2 ef }

  condition:
    any of them
}