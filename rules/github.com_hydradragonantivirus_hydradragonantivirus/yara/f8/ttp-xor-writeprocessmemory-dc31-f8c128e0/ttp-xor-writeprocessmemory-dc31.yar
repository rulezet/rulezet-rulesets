rule TTP_XOR_WriteProcessMemory_dc31 {
  strings:
    $key_dc31 = { 8b 43 [2] b9 61 [2] bf 54 [2] 91 54 [2] ae 48 }

  condition:
    any of them
}