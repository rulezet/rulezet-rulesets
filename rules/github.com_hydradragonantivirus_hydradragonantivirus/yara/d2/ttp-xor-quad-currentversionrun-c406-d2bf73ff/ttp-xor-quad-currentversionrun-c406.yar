rule TTP_XOR_QUAD_CurrentVersionRun_c406 {
  strings:
    $key_c406 = { 97 69 [2] b3 67 [2] 98 4b [2] b6 69 [2] a2 72 [2] ad 68 [2] b3 75 [2] b1 74 [2] aa 72 [2] b6 75 [2] aa 5a }

  condition:
    any of them
}