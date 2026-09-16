rule TTP_XOR_QUAD_CurrentVersionRun_e8e3 {
  strings:
    $key_e8e3 = { bb 8c [2] 9f 82 [2] b4 ae [2] 9a 8c [2] 8e 97 [2] 81 8d [2] 9f 90 [2] 9d 91 [2] 86 97 [2] 9a 90 [2] 86 bf }

  condition:
    any of them
}