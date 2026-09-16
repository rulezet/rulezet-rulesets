rule TTP_XOR_QUAD_CurrentVersionRun_c306 {
  strings:
    $key_c306 = { 90 69 [2] b4 67 [2] 9f 4b [2] b1 69 [2] a5 72 [2] aa 68 [2] b4 75 [2] b6 74 [2] ad 72 [2] b1 75 [2] ad 5a }

  condition:
    any of them
}