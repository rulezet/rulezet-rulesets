rule TTP_XOR_WriteProcessMemory_a4b5 {
  strings:
    $key_a4b5 = { f3 c7 [2] c1 e5 [2] c7 d0 [2] e9 d0 [2] d6 cc }

  condition:
    any of them
}