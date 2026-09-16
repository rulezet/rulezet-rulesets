rule TTP_XOR_QUAD_CurrentVersionRun_c222 {
  strings:
    $key_c222 = { 91 4d [2] b5 43 [2] 9e 6f [2] b0 4d [2] a4 56 [2] ab 4c [2] b5 51 [2] b7 50 [2] ac 56 [2] b0 51 [2] ac 7e }

  condition:
    any of them
}