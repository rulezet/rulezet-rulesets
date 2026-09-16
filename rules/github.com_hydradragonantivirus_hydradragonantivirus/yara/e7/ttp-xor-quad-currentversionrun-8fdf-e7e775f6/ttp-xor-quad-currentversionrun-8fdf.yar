rule TTP_XOR_QUAD_CurrentVersionRun_8fdf {
  strings:
    $key_8fdf = { dc b0 [2] f8 be [2] d3 92 [2] fd b0 [2] e9 ab [2] e6 b1 [2] f8 ac [2] fa ad [2] e1 ab [2] fd ac [2] e1 83 }

  condition:
    any of them
}