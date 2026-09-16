rule TTP_XOR_QUAD_CurrentVersionRun_0ae3 {
  strings:
    $key_0ae3 = { 59 8c [2] 7d 82 [2] 56 ae [2] 78 8c [2] 6c 97 [2] 63 8d [2] 7d 90 [2] 7f 91 [2] 64 97 [2] 78 90 [2] 64 bf }

  condition:
    any of them
}