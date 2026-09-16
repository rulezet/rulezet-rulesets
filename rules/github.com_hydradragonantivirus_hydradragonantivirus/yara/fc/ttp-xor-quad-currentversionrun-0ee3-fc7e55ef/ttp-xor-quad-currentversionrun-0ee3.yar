rule TTP_XOR_QUAD_CurrentVersionRun_0ee3 {
  strings:
    $key_0ee3 = { 5d 8c [2] 79 82 [2] 52 ae [2] 7c 8c [2] 68 97 [2] 67 8d [2] 79 90 [2] 7b 91 [2] 60 97 [2] 7c 90 [2] 60 bf }

  condition:
    any of them
}