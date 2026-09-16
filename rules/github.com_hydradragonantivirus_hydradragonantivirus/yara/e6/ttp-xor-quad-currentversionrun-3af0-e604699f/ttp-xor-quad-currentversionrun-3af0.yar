rule TTP_XOR_QUAD_CurrentVersionRun_3af0 {
  strings:
    $key_3af0 = { 69 9f [2] 4d 91 [2] 66 bd [2] 48 9f [2] 5c 84 [2] 53 9e [2] 4d 83 [2] 4f 82 [2] 54 84 [2] 48 83 [2] 54 ac }

  condition:
    any of them
}