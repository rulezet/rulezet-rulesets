rule TTP_XOR_QUAD_CurrentVersionRun_2ff0 {
  strings:
    $key_2ff0 = { 7c 9f [2] 58 91 [2] 73 bd [2] 5d 9f [2] 49 84 [2] 46 9e [2] 58 83 [2] 5a 82 [2] 41 84 [2] 5d 83 [2] 41 ac }

  condition:
    any of them
}