rule TTP_XOR_WriteProcessMemory_46fa {
  strings:
    $key_46fa = { 11 88 [2] 23 aa [2] 25 9f [2] 0b 9f [2] 34 83 }

  condition:
    any of them
}