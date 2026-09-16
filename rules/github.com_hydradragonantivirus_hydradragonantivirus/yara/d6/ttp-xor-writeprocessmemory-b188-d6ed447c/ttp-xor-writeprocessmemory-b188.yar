rule TTP_XOR_WriteProcessMemory_b188 {
  strings:
    $key_b188 = { e6 fa [2] d4 d8 [2] d2 ed [2] fc ed [2] c3 f1 }

  condition:
    any of them
}