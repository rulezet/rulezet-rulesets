rule TTP_XOR_QUAD_CurrentVersionRun_b6a2 {
  strings:
    $key_b6a2 = { e5 cd [2] c1 c3 [2] ea ef [2] c4 cd [2] d0 d6 [2] df cc [2] c1 d1 [2] c3 d0 [2] d8 d6 [2] c4 d1 [2] d8 fe }

  condition:
    any of them
}