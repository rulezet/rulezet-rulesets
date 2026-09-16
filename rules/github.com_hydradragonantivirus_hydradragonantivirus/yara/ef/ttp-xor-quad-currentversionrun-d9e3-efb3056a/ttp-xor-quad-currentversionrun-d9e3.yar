rule TTP_XOR_QUAD_CurrentVersionRun_d9e3 {
  strings:
    $key_d9e3 = { 8a 8c [2] ae 82 [2] 85 ae [2] ab 8c [2] bf 97 [2] b0 8d [2] ae 90 [2] ac 91 [2] b7 97 [2] ab 90 [2] b7 bf }

  condition:
    any of them
}