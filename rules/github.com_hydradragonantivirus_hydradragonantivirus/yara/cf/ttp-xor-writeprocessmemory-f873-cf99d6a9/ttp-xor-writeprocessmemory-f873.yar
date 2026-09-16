rule TTP_XOR_WriteProcessMemory_f873 {
  strings:
    $key_f873 = { af 01 [2] 9d 23 [2] 9b 16 [2] b5 16 [2] 8a 0a }

  condition:
    any of them
}