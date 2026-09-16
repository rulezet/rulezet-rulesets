rule TTP_XOR_QUAD_CurrentVersionRun_2ee3 {
  strings:
    $key_2ee3 = { 7d 8c [2] 59 82 [2] 72 ae [2] 5c 8c [2] 48 97 [2] 47 8d [2] 59 90 [2] 5b 91 [2] 40 97 [2] 5c 90 [2] 40 bf }

  condition:
    any of them
}