rule TTP_XOR_QUAD_CurrentVersionRun_f7e3 {
  strings:
    $key_f7e3 = { a4 8c [2] 80 82 [2] ab ae [2] 85 8c [2] 91 97 [2] 9e 8d [2] 80 90 [2] 82 91 [2] 99 97 [2] 85 90 [2] 99 bf }

  condition:
    any of them
}