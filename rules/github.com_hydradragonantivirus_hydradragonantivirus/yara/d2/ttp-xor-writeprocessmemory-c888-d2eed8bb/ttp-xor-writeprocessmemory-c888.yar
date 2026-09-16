rule TTP_XOR_WriteProcessMemory_c888 {
  strings:
    $key_c888 = { 9f fa [2] ad d8 [2] ab ed [2] 85 ed [2] ba f1 }

  condition:
    any of them
}