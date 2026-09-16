rule TTP_XOR_WriteProcessMemory_a0b5 {
  strings:
    $key_a0b5 = { f7 c7 [2] c5 e5 [2] c3 d0 [2] ed d0 [2] d2 cc }

  condition:
    any of them
}