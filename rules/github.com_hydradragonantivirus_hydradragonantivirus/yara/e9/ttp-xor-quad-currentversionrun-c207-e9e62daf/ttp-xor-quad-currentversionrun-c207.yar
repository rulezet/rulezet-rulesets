rule TTP_XOR_QUAD_CurrentVersionRun_c207 {
  strings:
    $key_c207 = { 91 68 [2] b5 66 [2] 9e 4a [2] b0 68 [2] a4 73 [2] ab 69 [2] b5 74 [2] b7 75 [2] ac 73 [2] b0 74 [2] ac 5b }

  condition:
    any of them
}