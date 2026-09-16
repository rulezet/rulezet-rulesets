rule TTP_XOR_QUAD_CurrentVersionRun_a7a2 {
  strings:
    $key_a7a2 = { f4 cd [2] d0 c3 [2] fb ef [2] d5 cd [2] c1 d6 [2] ce cc [2] d0 d1 [2] d2 d0 [2] c9 d6 [2] d5 d1 [2] c9 fe }

  condition:
    any of them
}