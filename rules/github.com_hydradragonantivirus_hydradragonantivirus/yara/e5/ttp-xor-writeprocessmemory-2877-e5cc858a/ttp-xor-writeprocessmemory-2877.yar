rule TTP_XOR_WriteProcessMemory_2877 {
  strings:
    $key_2877 = { 7f 05 [2] 4d 27 [2] 4b 12 [2] 65 12 [2] 5a 0e }

  condition:
    any of them
}