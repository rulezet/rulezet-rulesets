rule TTP_XOR_QUAD_CurrentVersionRun_c2e2 {
  strings:
    $key_c2e2 = { 91 8d [2] b5 83 [2] 9e af [2] b0 8d [2] a4 96 [2] ab 8c [2] b5 91 [2] b7 90 [2] ac 96 [2] b0 91 [2] ac be }

  condition:
    any of them
}