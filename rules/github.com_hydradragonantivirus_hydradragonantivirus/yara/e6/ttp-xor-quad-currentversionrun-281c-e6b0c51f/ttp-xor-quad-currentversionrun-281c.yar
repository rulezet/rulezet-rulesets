rule TTP_XOR_QUAD_CurrentVersionRun_281c {
  strings:
    $key_281c = { 7b 73 [2] 5f 7d [2] 74 51 [2] 5a 73 [2] 4e 68 [2] 41 72 [2] 5f 6f [2] 5d 6e [2] 46 68 [2] 5a 6f [2] 46 40 }

  condition:
    any of them
}