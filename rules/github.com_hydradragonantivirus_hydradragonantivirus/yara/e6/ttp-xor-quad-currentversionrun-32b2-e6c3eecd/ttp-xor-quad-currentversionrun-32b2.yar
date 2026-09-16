rule TTP_XOR_QUAD_CurrentVersionRun_32b2 {
  strings:
    $key_32b2 = { 61 dd [2] 45 d3 [2] 6e ff [2] 40 dd [2] 54 c6 [2] 5b dc [2] 45 c1 [2] 47 c0 [2] 5c c6 [2] 40 c1 [2] 5c ee }

  condition:
    any of them
}