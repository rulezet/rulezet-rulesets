rule TTP_XOR_QUAD_CurrentVersionRun_c512 {
  strings:
    $key_c512 = { 96 7d [2] b2 73 [2] 99 5f [2] b7 7d [2] a3 66 [2] ac 7c [2] b2 61 [2] b0 60 [2] ab 66 [2] b7 61 [2] ab 4e }

  condition:
    any of them
}