rule TTP_XOR_QUAD_CurrentVersionRun_1df0 {
  strings:
    $key_1df0 = { 4e 9f [2] 6a 91 [2] 41 bd [2] 6f 9f [2] 7b 84 [2] 74 9e [2] 6a 83 [2] 68 82 [2] 73 84 [2] 6f 83 [2] 73 ac }

  condition:
    any of them
}