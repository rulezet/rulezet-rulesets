rule TTP_XOR_QUAD_CurrentVersionRun_35b2 {
  strings:
    $key_35b2 = { 66 dd [2] 42 d3 [2] 69 ff [2] 47 dd [2] 53 c6 [2] 5c dc [2] 42 c1 [2] 40 c0 [2] 5b c6 [2] 47 c1 [2] 5b ee }

  condition:
    any of them
}