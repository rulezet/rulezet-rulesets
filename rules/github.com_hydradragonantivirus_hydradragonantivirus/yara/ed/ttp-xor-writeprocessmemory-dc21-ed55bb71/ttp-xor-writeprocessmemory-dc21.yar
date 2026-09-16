rule TTP_XOR_WriteProcessMemory_dc21 {
  strings:
    $key_dc21 = { 8b 53 [2] b9 71 [2] bf 44 [2] 91 44 [2] ae 58 }

  condition:
    any of them
}