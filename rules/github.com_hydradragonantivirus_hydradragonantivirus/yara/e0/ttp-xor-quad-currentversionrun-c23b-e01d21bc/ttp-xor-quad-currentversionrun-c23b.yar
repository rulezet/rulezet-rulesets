rule TTP_XOR_QUAD_CurrentVersionRun_c23b {
  strings:
    $key_c23b = { 91 54 [2] b5 5a [2] 9e 76 [2] b0 54 [2] a4 4f [2] ab 55 [2] b5 48 [2] b7 49 [2] ac 4f [2] b0 48 [2] ac 67 }

  condition:
    any of them
}