rule TTP_XOR_QUAD_CurrentVersionRun_c235 {
  strings:
    $key_c235 = { 91 5a [2] b5 54 [2] 9e 78 [2] b0 5a [2] a4 41 [2] ab 5b [2] b5 46 [2] b7 47 [2] ac 41 [2] b0 46 [2] ac 69 }

  condition:
    any of them
}