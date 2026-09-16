rule TTP_XOR_WriteProcessMemory_e915 {
  strings:
    $key_e915 = { be 67 [2] 8c 45 [2] 8a 70 [2] a4 70 [2] 9b 6c }

  condition:
    any of them
}