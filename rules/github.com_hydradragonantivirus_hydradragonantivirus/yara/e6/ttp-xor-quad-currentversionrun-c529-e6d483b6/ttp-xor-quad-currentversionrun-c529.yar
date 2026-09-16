rule TTP_XOR_QUAD_CurrentVersionRun_c529 {
  strings:
    $key_c529 = { 96 46 [2] b2 48 [2] 99 64 [2] b7 46 [2] a3 5d [2] ac 47 [2] b2 5a [2] b0 5b [2] ab 5d [2] b7 5a [2] ab 75 }

  condition:
    any of them
}