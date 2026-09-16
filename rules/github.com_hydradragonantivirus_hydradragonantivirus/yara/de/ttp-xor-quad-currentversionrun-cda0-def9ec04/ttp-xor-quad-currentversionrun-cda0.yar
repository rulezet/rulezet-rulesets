rule TTP_XOR_QUAD_CurrentVersionRun_cda0 {
  strings:
    $key_cda0 = { 9e cf [2] ba c1 [2] 91 ed [2] bf cf [2] ab d4 [2] a4 ce [2] ba d3 [2] b8 d2 [2] a3 d4 [2] bf d3 [2] a3 fc }

  condition:
    any of them
}