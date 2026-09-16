rule TTP_XOR_WriteProcessMemory_3227 {
  strings:
    $key_3227 = { 65 55 [2] 57 77 [2] 51 42 [2] 7f 42 [2] 40 5e }

  condition:
    any of them
}