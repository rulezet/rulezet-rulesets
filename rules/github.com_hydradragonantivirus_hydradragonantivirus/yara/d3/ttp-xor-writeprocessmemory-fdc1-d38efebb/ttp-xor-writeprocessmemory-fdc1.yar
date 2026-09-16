rule TTP_XOR_WriteProcessMemory_fdc1 {
  strings:
    $key_fdc1 = { aa b3 [2] 98 91 [2] 9e a4 [2] b0 a4 [2] 8f b8 }

  condition:
    any of them
}