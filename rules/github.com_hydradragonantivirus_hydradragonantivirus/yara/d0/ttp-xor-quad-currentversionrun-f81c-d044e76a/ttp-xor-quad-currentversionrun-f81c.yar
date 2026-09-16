rule TTP_XOR_QUAD_CurrentVersionRun_f81c {
  strings:
    $key_f81c = { ab 73 [2] 8f 7d [2] a4 51 [2] 8a 73 [2] 9e 68 [2] 91 72 [2] 8f 6f [2] 8d 6e [2] 96 68 [2] 8a 6f [2] 96 40 }

  condition:
    any of them
}