rule TTP_XOR_WriteProcessMemory_11fa {
  strings:
    $key_11fa = { 46 88 [2] 74 aa [2] 72 9f [2] 5c 9f [2] 63 83 }

  condition:
    any of them
}