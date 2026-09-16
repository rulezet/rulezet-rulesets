rule TTP_XOR_QUAD_CurrentVersionRun_fbe3 {
  strings:
    $key_fbe3 = { a8 8c [2] 8c 82 [2] a7 ae [2] 89 8c [2] 9d 97 [2] 92 8d [2] 8c 90 [2] 8e 91 [2] 95 97 [2] 89 90 [2] 95 bf }

  condition:
    any of them
}