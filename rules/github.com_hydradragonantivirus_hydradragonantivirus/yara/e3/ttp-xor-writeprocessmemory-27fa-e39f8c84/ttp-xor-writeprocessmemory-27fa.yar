rule TTP_XOR_WriteProcessMemory_27fa {
  strings:
    $key_27fa = { 70 88 [2] 42 aa [2] 44 9f [2] 6a 9f [2] 55 83 }

  condition:
    any of them
}