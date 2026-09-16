rule TTP_XOR_QUAD_CurrentVersionRun_c513 {
  strings:
    $key_c513 = { 96 7c [2] b2 72 [2] 99 5e [2] b7 7c [2] a3 67 [2] ac 7d [2] b2 60 [2] b0 61 [2] ab 67 [2] b7 60 [2] ab 4f }

  condition:
    any of them
}