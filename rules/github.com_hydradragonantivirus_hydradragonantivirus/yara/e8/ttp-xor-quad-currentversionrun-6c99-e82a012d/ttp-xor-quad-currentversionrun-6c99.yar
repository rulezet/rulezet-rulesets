rule TTP_XOR_QUAD_CurrentVersionRun_6c99 {
  strings:
    $key_6c99 = { 3f f6 [2] 1b f8 [2] 30 d4 [2] 1e f6 [2] 0a ed [2] 05 f7 [2] 1b ea [2] 19 eb [2] 02 ed [2] 1e ea [2] 02 c5 }

  condition:
    any of them
}