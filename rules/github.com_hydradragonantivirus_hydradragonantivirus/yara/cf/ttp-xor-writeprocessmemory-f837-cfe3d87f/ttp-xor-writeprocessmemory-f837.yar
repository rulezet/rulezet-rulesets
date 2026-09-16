rule TTP_XOR_WriteProcessMemory_f837 {
  strings:
    $key_f837 = { af 45 [2] 9d 67 [2] 9b 52 [2] b5 52 [2] 8a 4e }

  condition:
    any of them
}