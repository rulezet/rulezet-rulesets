rule TTP_XOR_QUAD_CurrentVersionRun_6de3 {
  strings:
    $key_6de3 = { 3e 8c [2] 1a 82 [2] 31 ae [2] 1f 8c [2] 0b 97 [2] 04 8d [2] 1a 90 [2] 18 91 [2] 03 97 [2] 1f 90 [2] 03 bf }

  condition:
    any of them
}