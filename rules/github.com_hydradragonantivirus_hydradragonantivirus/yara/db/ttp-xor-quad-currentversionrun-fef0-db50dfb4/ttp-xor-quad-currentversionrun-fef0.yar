rule TTP_XOR_QUAD_CurrentVersionRun_fef0 {
  strings:
    $key_fef0 = { ad 9f [2] 89 91 [2] a2 bd [2] 8c 9f [2] 98 84 [2] 97 9e [2] 89 83 [2] 8b 82 [2] 90 84 [2] 8c 83 [2] 90 ac }

  condition:
    any of them
}