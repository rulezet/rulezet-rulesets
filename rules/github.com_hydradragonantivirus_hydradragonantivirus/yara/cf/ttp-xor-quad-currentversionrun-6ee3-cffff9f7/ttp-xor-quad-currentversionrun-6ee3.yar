rule TTP_XOR_QUAD_CurrentVersionRun_6ee3 {
  strings:
    $key_6ee3 = { 3d 8c [2] 19 82 [2] 32 ae [2] 1c 8c [2] 08 97 [2] 07 8d [2] 19 90 [2] 1b 91 [2] 00 97 [2] 1c 90 [2] 00 bf }

  condition:
    any of them
}