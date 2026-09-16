rule TTP_XOR_QUAD_CurrentVersionRun_31e3 {
  strings:
    $key_31e3 = { 62 8c [2] 46 82 [2] 6d ae [2] 43 8c [2] 57 97 [2] 58 8d [2] 46 90 [2] 44 91 [2] 5f 97 [2] 43 90 [2] 5f bf }

  condition:
    any of them
}