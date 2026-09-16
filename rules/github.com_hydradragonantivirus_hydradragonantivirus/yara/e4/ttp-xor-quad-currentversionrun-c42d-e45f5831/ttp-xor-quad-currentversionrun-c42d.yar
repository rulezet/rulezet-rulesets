rule TTP_XOR_QUAD_CurrentVersionRun_c42d {
  strings:
    $key_c42d = { 97 42 [2] b3 4c [2] 98 60 [2] b6 42 [2] a2 59 [2] ad 43 [2] b3 5e [2] b1 5f [2] aa 59 [2] b6 5e [2] aa 71 }

  condition:
    any of them
}