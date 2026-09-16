rule TTP_XOR_QUAD_CurrentVersionRun_c5f0 {
  strings:
    $key_c5f0 = { 96 9f [2] b2 91 [2] 99 bd [2] b7 9f [2] a3 84 [2] ac 9e [2] b2 83 [2] b0 82 [2] ab 84 [2] b7 83 [2] ab ac }

  condition:
    any of them
}