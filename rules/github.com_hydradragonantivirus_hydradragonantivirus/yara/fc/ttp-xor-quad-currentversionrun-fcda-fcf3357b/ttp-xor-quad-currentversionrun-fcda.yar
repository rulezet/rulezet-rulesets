rule TTP_XOR_QUAD_CurrentVersionRun_fcda {
  strings:
    $key_fcda = { af b5 [2] 8b bb [2] a0 97 [2] 8e b5 [2] 9a ae [2] 95 b4 [2] 8b a9 [2] 89 a8 [2] 92 ae [2] 8e a9 [2] 92 86 }

  condition:
    any of them
}