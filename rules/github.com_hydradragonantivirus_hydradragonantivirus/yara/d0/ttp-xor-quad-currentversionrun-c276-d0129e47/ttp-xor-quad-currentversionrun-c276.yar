rule TTP_XOR_QUAD_CurrentVersionRun_c276 {
  strings:
    $key_c276 = { 91 19 [2] b5 17 [2] 9e 3b [2] b0 19 [2] a4 02 [2] ab 18 [2] b5 05 [2] b7 04 [2] ac 02 [2] b0 05 [2] ac 2a }

  condition:
    any of them
}