rule TTP_XOR_QUAD_CurrentVersionRun_5bf0 {
  strings:
    $key_5bf0 = { 08 9f [2] 2c 91 [2] 07 bd [2] 29 9f [2] 3d 84 [2] 32 9e [2] 2c 83 [2] 2e 82 [2] 35 84 [2] 29 83 [2] 35 ac }

  condition:
    any of them
}