rule TTP_XOR_QUAD_CurrentVersionRun_c43c {
  strings:
    $key_c43c = { 97 53 [2] b3 5d [2] 98 71 [2] b6 53 [2] a2 48 [2] ad 52 [2] b3 4f [2] b1 4e [2] aa 48 [2] b6 4f [2] aa 60 }

  condition:
    any of them
}