rule TTP_XOR_QUAD_CurrentVersionRun_3fe3 {
  strings:
    $key_3fe3 = { 6c 8c [2] 48 82 [2] 63 ae [2] 4d 8c [2] 59 97 [2] 56 8d [2] 48 90 [2] 4a 91 [2] 51 97 [2] 4d 90 [2] 51 bf }

  condition:
    any of them
}