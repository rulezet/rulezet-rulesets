rule TTP_XOR_QUAD_CurrentVersionRun_c212 {
  strings:
    $key_c212 = { 91 7d [2] b5 73 [2] 9e 5f [2] b0 7d [2] a4 66 [2] ab 7c [2] b5 61 [2] b7 60 [2] ac 66 [2] b0 61 [2] ac 4e }

  condition:
    any of them
}