rule TTP_XOR_QUAD_CurrentVersionRun_fee3 {
  strings:
    $key_fee3 = { ad 8c [2] 89 82 [2] a2 ae [2] 8c 8c [2] 98 97 [2] 97 8d [2] 89 90 [2] 8b 91 [2] 90 97 [2] 8c 90 [2] 90 bf }

  condition:
    any of them
}