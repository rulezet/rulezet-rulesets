rule TTP_XOR_WriteProcessMemory_2c39 {
  strings:
    $key_2c39 = { 7b 4b [2] 49 69 [2] 4f 5c [2] 61 5c [2] 5e 40 }

  condition:
    any of them
}