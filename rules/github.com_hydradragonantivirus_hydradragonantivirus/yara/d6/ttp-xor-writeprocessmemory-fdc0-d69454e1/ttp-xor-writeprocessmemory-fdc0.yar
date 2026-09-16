rule TTP_XOR_WriteProcessMemory_fdc0 {
  strings:
    $key_fdc0 = { aa b2 [2] 98 90 [2] 9e a5 [2] b0 a5 [2] 8f b9 }

  condition:
    any of them
}