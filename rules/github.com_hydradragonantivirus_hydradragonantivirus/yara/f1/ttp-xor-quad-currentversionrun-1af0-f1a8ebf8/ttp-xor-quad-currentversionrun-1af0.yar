rule TTP_XOR_QUAD_CurrentVersionRun_1af0 {
  strings:
    $key_1af0 = { 49 9f [2] 6d 91 [2] 46 bd [2] 68 9f [2] 7c 84 [2] 73 9e [2] 6d 83 [2] 6f 82 [2] 74 84 [2] 68 83 [2] 74 ac }

  condition:
    any of them
}