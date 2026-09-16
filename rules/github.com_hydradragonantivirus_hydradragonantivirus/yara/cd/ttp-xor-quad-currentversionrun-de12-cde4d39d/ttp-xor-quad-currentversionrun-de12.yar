rule TTP_XOR_QUAD_CurrentVersionRun_de12 {
  strings:
    $key_de12 = { 8d 7d [2] a9 73 [2] 82 5f [2] ac 7d [2] b8 66 [2] b7 7c [2] a9 61 [2] ab 60 [2] b0 66 [2] ac 61 [2] b0 4e }

  condition:
    any of them
}