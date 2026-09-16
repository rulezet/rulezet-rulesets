rule TTP_XOR_WriteProcessMemory_0c77 {
  strings:
    $key_0c77 = { 5b 05 [2] 69 27 [2] 6f 12 [2] 41 12 [2] 7e 0e }

  condition:
    any of them
}