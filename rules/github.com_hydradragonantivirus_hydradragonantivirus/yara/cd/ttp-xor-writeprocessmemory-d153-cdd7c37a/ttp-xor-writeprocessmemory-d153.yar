rule TTP_XOR_WriteProcessMemory_d153 {
  strings:
    $key_d153 = { 86 21 [2] b4 03 [2] b2 36 [2] 9c 36 [2] a3 2a }

  condition:
    any of them
}