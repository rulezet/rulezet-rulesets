rule TTP_XOR_WriteProcessMemory_c079 {
  strings:
    $key_c079 = { 97 0b [2] a5 29 [2] a3 1c [2] 8d 1c [2] b2 00 }

  condition:
    any of them
}