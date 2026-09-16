rule TTP_XOR_QUAD_CurrentVersionRun_f1e3 {
  strings:
    $key_f1e3 = { a2 8c [2] 86 82 [2] ad ae [2] 83 8c [2] 97 97 [2] 98 8d [2] 86 90 [2] 84 91 [2] 9f 97 [2] 83 90 [2] 9f bf }

  condition:
    any of them
}