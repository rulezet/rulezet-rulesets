rule TTP_XOR_QUAD_CurrentVersionRun_06a2 {
  strings:
    $key_06a2 = { 55 cd [2] 71 c3 [2] 5a ef [2] 74 cd [2] 60 d6 [2] 6f cc [2] 71 d1 [2] 73 d0 [2] 68 d6 [2] 74 d1 [2] 68 fe }

  condition:
    any of them
}