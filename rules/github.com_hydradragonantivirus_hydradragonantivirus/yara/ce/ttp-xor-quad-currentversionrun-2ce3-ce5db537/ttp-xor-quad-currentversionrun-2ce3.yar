rule TTP_XOR_QUAD_CurrentVersionRun_2ce3 {
  strings:
    $key_2ce3 = { 7f 8c [2] 5b 82 [2] 70 ae [2] 5e 8c [2] 4a 97 [2] 45 8d [2] 5b 90 [2] 59 91 [2] 42 97 [2] 5e 90 [2] 42 bf }

  condition:
    any of them
}