rule TTP_XOR_QUAD_CurrentVersionRun_d2a2 {
  strings:
    $key_d2a2 = { 81 cd [2] a5 c3 [2] 8e ef [2] a0 cd [2] b4 d6 [2] bb cc [2] a5 d1 [2] a7 d0 [2] bc d6 [2] a0 d1 [2] bc fe }

  condition:
    any of them
}