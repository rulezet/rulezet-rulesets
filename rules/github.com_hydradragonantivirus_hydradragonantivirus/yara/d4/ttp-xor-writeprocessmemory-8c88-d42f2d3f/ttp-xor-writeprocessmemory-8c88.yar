rule TTP_XOR_WriteProcessMemory_8c88 {
  strings:
    $key_8c88 = { db fa [2] e9 d8 [2] ef ed [2] c1 ed [2] fe f1 }

  condition:
    any of them
}