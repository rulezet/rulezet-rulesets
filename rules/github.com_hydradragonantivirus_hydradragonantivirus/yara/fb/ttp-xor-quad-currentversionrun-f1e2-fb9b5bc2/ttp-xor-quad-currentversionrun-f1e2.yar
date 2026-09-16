rule TTP_XOR_QUAD_CurrentVersionRun_f1e2 {
  strings:
    $key_f1e2 = { a2 8d [2] 86 83 [2] ad af [2] 83 8d [2] 97 96 [2] 98 8c [2] 86 91 [2] 84 90 [2] 9f 96 [2] 83 91 [2] 9f be }

  condition:
    any of them
}