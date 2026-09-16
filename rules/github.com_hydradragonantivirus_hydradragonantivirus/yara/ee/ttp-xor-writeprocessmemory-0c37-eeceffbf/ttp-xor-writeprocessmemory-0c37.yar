rule TTP_XOR_WriteProcessMemory_0c37 {
  strings:
    $key_0c37 = { 5b 45 [2] 69 67 [2] 6f 52 [2] 41 52 [2] 7e 4e }

  condition:
    any of them
}