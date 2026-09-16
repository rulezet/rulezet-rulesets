rule TTP_XOR_WriteProcessMemory_f851 {
  strings:
    $key_f851 = { af 23 [2] 9d 01 [2] 9b 34 [2] b5 34 [2] 8a 28 }

  condition:
    any of them
}