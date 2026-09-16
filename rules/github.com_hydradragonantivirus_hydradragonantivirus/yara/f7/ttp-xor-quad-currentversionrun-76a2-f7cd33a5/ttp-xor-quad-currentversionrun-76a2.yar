rule TTP_XOR_QUAD_CurrentVersionRun_76a2 {
  strings:
    $key_76a2 = { 25 cd [2] 01 c3 [2] 2a ef [2] 04 cd [2] 10 d6 [2] 1f cc [2] 01 d1 [2] 03 d0 [2] 18 d6 [2] 04 d1 [2] 18 fe }

  condition:
    any of them
}