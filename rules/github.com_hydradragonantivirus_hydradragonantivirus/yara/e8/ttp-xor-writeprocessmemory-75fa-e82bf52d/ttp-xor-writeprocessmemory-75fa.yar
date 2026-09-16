rule TTP_XOR_WriteProcessMemory_75fa {
  strings:
    $key_75fa = { 22 88 [2] 10 aa [2] 16 9f [2] 38 9f [2] 07 83 }

  condition:
    any of them
}