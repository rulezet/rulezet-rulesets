rule TTP_XOR_QUAD_CurrentVersionRun_e2b2 {
  strings:
    $key_e2b2 = { b1 dd [2] 95 d3 [2] be ff [2] 90 dd [2] 84 c6 [2] 8b dc [2] 95 c1 [2] 97 c0 [2] 8c c6 [2] 90 c1 [2] 8c ee }

  condition:
    any of them
}