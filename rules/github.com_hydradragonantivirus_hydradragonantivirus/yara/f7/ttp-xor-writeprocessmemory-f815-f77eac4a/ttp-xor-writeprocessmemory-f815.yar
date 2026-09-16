rule TTP_XOR_WriteProcessMemory_f815 {
  strings:
    $key_f815 = { af 67 [2] 9d 45 [2] 9b 70 [2] b5 70 [2] 8a 6c }

  condition:
    any of them
}