rule TTP_XOR_WriteProcessMemory_3f47 {
  strings:
    $key_3f47 = { 68 35 [2] 5a 17 [2] 5c 22 [2] 72 22 [2] 4d 3e }

  condition:
    any of them
}