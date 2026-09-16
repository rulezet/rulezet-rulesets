rule TTP_XOR_QUAD_CurrentVersionRun_d7e3 {
  strings:
    $key_d7e3 = { 84 8c [2] a0 82 [2] 8b ae [2] a5 8c [2] b1 97 [2] be 8d [2] a0 90 [2] a2 91 [2] b9 97 [2] a5 90 [2] b9 bf }

  condition:
    any of them
}