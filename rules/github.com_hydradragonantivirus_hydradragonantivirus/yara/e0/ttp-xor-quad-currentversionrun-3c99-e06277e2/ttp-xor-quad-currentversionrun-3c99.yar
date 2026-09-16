rule TTP_XOR_QUAD_CurrentVersionRun_3c99 {
  strings:
    $key_3c99 = { 6f f6 [2] 4b f8 [2] 60 d4 [2] 4e f6 [2] 5a ed [2] 55 f7 [2] 4b ea [2] 49 eb [2] 52 ed [2] 4e ea [2] 52 c5 }

  condition:
    any of them
}