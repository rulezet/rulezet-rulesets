rule TTP_XOR_WriteProcessMemory_f827 {
  strings:
    $key_f827 = { af 55 [2] 9d 77 [2] 9b 42 [2] b5 42 [2] 8a 5e }

  condition:
    any of them
}