rule TTP_XOR_QUAD_CurrentVersionRun_24b3 {
  strings:
    $key_24b3 = { 77 dc [2] 53 d2 [2] 78 fe [2] 56 dc [2] 42 c7 [2] 4d dd [2] 53 c0 [2] 51 c1 [2] 4a c7 [2] 56 c0 [2] 4a ef }

  condition:
    any of them
}