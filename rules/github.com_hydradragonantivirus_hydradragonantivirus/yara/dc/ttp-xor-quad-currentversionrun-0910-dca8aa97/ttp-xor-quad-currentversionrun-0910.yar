rule TTP_XOR_QUAD_CurrentVersionRun_0910 {
  strings:
    $key_0910 = { 5a 7f [2] 7e 71 [2] 55 5d [2] 7b 7f [2] 6f 64 [2] 60 7e [2] 7e 63 [2] 7c 62 [2] 67 64 [2] 7b 63 [2] 67 4c }

  condition:
    any of them
}