rule TTP_XOR_QUAD_CurrentVersionRun_38f0 {
  strings:
    $key_38f0 = { 6b 9f [2] 4f 91 [2] 64 bd [2] 4a 9f [2] 5e 84 [2] 51 9e [2] 4f 83 [2] 4d 82 [2] 56 84 [2] 4a 83 [2] 56 ac }

  condition:
    any of them
}